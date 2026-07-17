package analytics

import (
	"math"
	"sort"
	"sync"
	"time"
)

// maxEndpointsPerIP caps how many distinct endpoints we remember per IP. A
// scanner can touch thousands of paths; without a cap one hostile IP could grow
// memory without bound. Beyond the cap we still count totals, just not new
// per-endpoint keys.
const maxEndpointsPerIP = 500

// alertWindowRetention bounds the windowed per-site/per-IP-minute data used for
// alert rule evaluation. This is independent of (and much shorter than) the
// main display retention, since rules only ever look at recent minutes -- there
// is no reason to keep an hour-by-hour IP breakdown for a week just because the
// user set analytics.retention to "168h".
const alertWindowRetention = 3 * time.Hour

// maxFailingEvents caps how many individual failing requests are retained for
// drill-down reports. Only status >= 400 is kept, so healthy traffic costs
// nothing; the cap bounds memory under an error storm. When exceeded, the
// oldest 10% is dropped in one shot (amortized O(1) per ingest).
const maxFailingEvents = 50000

// Event is one retained failing request, kept so reports can break its query
// string into per-key columns. Aggregates can't do that -- they've already
// thrown away the individual URLs.
type Event struct {
	Time     time.Time
	Site     string
	IP       string
	Method   string
	Path     string // raw path, no query
	Template string // normalized endpoint
	Query    string // raw (still percent-encoded) query string
	Status   int
}

// Store holds rolling in-memory traffic stats, safe for concurrent use: tailer
// goroutines write via Add, the API reads via the query methods.
type Store struct {
	mu        sync.RWMutex
	retention time.Duration

	minutes   map[int64]*bucket        // unix-minute -> status counts
	ips       map[string]*IPStat       // source ip -> behaviour
	endpoints map[string]*EndpointStat // "SITE\x00METHOD\x00TEMPLATE" -> health
	sites     map[string]*classCounts  // site -> status counts (cumulative, all time)

	// Windowed data for alert-rule evaluation only, bounded by alertWindowRetention
	// regardless of the main retention setting (see Evict).
	siteMinutes map[string]map[int64]*classCounts // site -> unix-minute -> counts
	ipMinutes   map[int64]map[string]int64         // unix-minute -> ip -> request count

	// Individual failing requests (status >= 400) for drill-down reports,
	// capped at maxFailingEvents and pruned by retention in Evict.
	events []Event
}

type bucket struct {
	classCounts
	codes map[int]int64 // exact status -> count, for detailed graphs
}

// classCounts tracks counts split by status class. Index 1..5 = 1xx..5xx.
type classCounts struct {
	total int64
	class [6]int64
}

func (c *classCounts) add(status int) {
	c.total++
	c.class[Class(status)]++
}

// IPStat is one source IP's aggregated behaviour.
type IPStat struct {
	IP        string
	First     time.Time
	Last      time.Time
	Sites     map[string]struct{}
	Endpoints map[string]int64 // endpoint template -> hits
	classCounts
}

// EndpointStat is one normalized endpoint's health.
type EndpointStat struct {
	Site     string
	Method   string
	Template string
	Last     time.Time
	ips      map[string]struct{}
	classCounts
}

// NewStore creates a Store retaining time-series buckets and idle IPs for the
// given window (defaults to 24h).
func NewStore(retention time.Duration) *Store {
	if retention <= 0 {
		retention = 24 * time.Hour
	}
	return &Store{
		retention:   retention,
		minutes:     make(map[int64]*bucket),
		ips:         make(map[string]*IPStat),
		endpoints:   make(map[string]*EndpointStat),
		sites:       make(map[string]*classCounts),
		siteMinutes: make(map[string]map[int64]*classCounts),
		ipMinutes:   make(map[int64]map[string]int64),
	}
}

// SetRetention updates the retention window (used on config reload).
func (s *Store) SetRetention(d time.Duration) {
	if d <= 0 {
		return
	}
	s.mu.Lock()
	s.retention = d
	s.mu.Unlock()
}

// Add ingests one record under its endpoint template.
func (s *Store) Add(r Record, template string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Time-series bucket (per minute).
	min := r.Time.Truncate(time.Minute).Unix()
	b := s.minutes[min]
	if b == nil {
		b = &bucket{codes: make(map[int]int64)}
		s.minutes[min] = b
	}
	b.add(r.Status)
	b.codes[r.Status]++

	// Per-site (cumulative).
	sc := s.sites[r.Site]
	if sc == nil {
		sc = &classCounts{}
		s.sites[r.Site] = sc
	}
	sc.add(r.Status)

	// Per-site-minute (windowed, for alert rules).
	sm := s.siteMinutes[r.Site]
	if sm == nil {
		sm = make(map[int64]*classCounts)
		s.siteMinutes[r.Site] = sm
	}
	smc := sm[min]
	if smc == nil {
		smc = &classCounts{}
		sm[min] = smc
	}
	smc.add(r.Status)

	// Per-IP-minute (windowed, for flood/scanner rules).
	im := s.ipMinutes[min]
	if im == nil {
		im = make(map[string]int64)
		s.ipMinutes[min] = im
	}
	im[r.IP]++

	// Per-IP.
	ip := s.ips[r.IP]
	if ip == nil {
		ip = &IPStat{IP: r.IP, First: r.Time, Sites: map[string]struct{}{}, Endpoints: map[string]int64{}}
		s.ips[r.IP] = ip
	}
	ip.Last = r.Time
	ip.Sites[r.Site] = struct{}{}
	if _, seen := ip.Endpoints[template]; seen || len(ip.Endpoints) < maxEndpointsPerIP {
		ip.Endpoints[template]++
	}
	ip.add(r.Status)

	// Per-endpoint.
	key := r.Site + "\x00" + r.Method + "\x00" + template
	ep := s.endpoints[key]
	if ep == nil {
		ep = &EndpointStat{Site: r.Site, Method: r.Method, Template: template, ips: map[string]struct{}{}}
		s.endpoints[key] = ep
	}
	ep.Last = r.Time
	ep.ips[r.IP] = struct{}{}
	ep.add(r.Status)

	// Retain individual failing requests for reports.
	if r.Status >= 400 {
		if len(s.events) >= maxFailingEvents {
			drop := maxFailingEvents / 10
			s.events = append(s.events[:0], s.events[drop:]...) // reuse backing array
		}
		s.events = append(s.events, Event{
			Time: r.Time, Site: r.Site, IP: r.IP, Method: r.Method,
			Path: r.Path, Template: template, Query: r.Query, Status: r.Status,
		})
	}
}

// Evict drops time-series buckets and idle IPs older than the retention window.
// Endpoint aggregates are kept (bounded by route cardinality, not time).
func (s *Store) Evict(now time.Time) {
	cutoffMin := now.Add(-s.retention).Truncate(time.Minute).Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	for m := range s.minutes {
		if m < cutoffMin {
			delete(s.minutes, m)
		}
	}
	idle := now.Add(-s.retention)
	for k, ip := range s.ips {
		if ip.Last.Before(idle) {
			delete(s.ips, k)
		}
	}

	// Windowed alert data uses its own short, fixed retention regardless of the
	// display retention above.
	alertCutoff := now.Add(-alertWindowRetention).Truncate(time.Minute).Unix()
	for site, mm := range s.siteMinutes {
		for m := range mm {
			if m < alertCutoff {
				delete(mm, m)
			}
		}
		if len(mm) == 0 {
			delete(s.siteMinutes, site)
		}
	}
	for m := range s.ipMinutes {
		if m < alertCutoff {
			delete(s.ipMinutes, m)
		}
	}

	// Prune failing events older than the display retention. Events are appended
	// in ingest (roughly time) order, so a single leading scan suffices.
	cut := now.Add(-s.retention)
	i := 0
	for i < len(s.events) && s.events[i].Time.Before(cut) {
		i++
	}
	if i > 0 {
		s.events = append(s.events[:0], s.events[i:]...)
	}
}

// ---- query helpers used by the API ----

// Rates converts class counts into fractions. success = 2xx, redirect = 3xx,
// failure = 4xx, error = 5xx. Together with any 1xx these sum to 1.0, so a UI
// can render a balanced 100% breakdown.
func (c classCounts) Rates() (success, redirect, failure, errRate float64) {
	if c.total == 0 {
		return 0, 0, 0, 0
	}
	t := float64(c.total)
	return float64(c.class[2]) / t, float64(c.class[3]) / t, float64(c.class[4]) / t, float64(c.class[5]) / t
}

// StatusClasses returns [1xx,2xx,3xx,4xx,5xx] counts.
func (c classCounts) StatusClasses() [5]int64 {
	return [5]int64{c.class[1], c.class[2], c.class[3], c.class[4], c.class[5]}
}

// TimePoint is one minute of the status time-series.
type TimePoint struct {
	Minute int64         `json:"minute"` // unix seconds, minute-aligned
	Total  int64         `json:"total"`
	C1xx   int64         `json:"c1xx"`
	C2xx   int64         `json:"c2xx"`
	C3xx   int64         `json:"c3xx"`
	C4xx   int64         `json:"c4xx"`
	C5xx   int64         `json:"c5xx"`
	Codes  map[int]int64 `json:"codes,omitempty"`
}

// TimeSeries returns per-minute points, oldest first. A window <= 0 returns
// every retained bucket (used for historical replay); otherwise only buckets
// within the last window.
func (s *Store) TimeSeries(window time.Duration, withCodes bool) []TimePoint {
	var cutoff int64 = math.MinInt64
	if window > 0 {
		cutoff = time.Now().Add(-window).Truncate(time.Minute).Unix()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	pts := make([]TimePoint, 0, len(s.minutes))
	for m, b := range s.minutes {
		if m < cutoff {
			continue
		}
		p := TimePoint{
			Minute: m, Total: b.total,
			C1xx: b.class[1], C2xx: b.class[2], C3xx: b.class[3], C4xx: b.class[4], C5xx: b.class[5],
		}
		if withCodes {
			p.Codes = b.codes
		}
		pts = append(pts, p)
	}
	sort.Slice(pts, func(i, j int) bool { return pts[i].Minute < pts[j].Minute })
	return pts
}

// SeriesBucket is one aggregated stick in a Series.
type SeriesBucket struct {
	Start int64 `json:"start"` // unix seconds, bucket start (local-aligned)
	Total int64 `json:"total"`
	C1xx  int64 `json:"c1xx"`
	C2xx  int64 `json:"c2xx"`
	C3xx  int64 `json:"c3xx"`
	C4xx  int64 `json:"c4xx"`
	C5xx  int64 `json:"c5xx"`
}

// Series is a fixed-shape chart: `count` buckets of `bucket` width, ending at an
// anchor. The anchor is the LATEST data timestamp (not wall-clock now) so charts
// line up with historical/static logs. anchor/start let the UI show real dates.
type Series struct {
	Anchor        int64          `json:"anchor"`         // unix secs, end of newest bucket
	Start         int64          `json:"start"`          // unix secs, start of oldest bucket
	BucketSeconds int64          `json:"bucket_seconds"` // width of each stick
	Count         int            `json:"count"`
	Buckets       []SeriesBucket `json:"buckets"`
}

// truncateLocal aligns t down to a multiple of d in LOCAL wall-clock time, so
// hour/day buckets land on local hour/midnight boundaries even in a +05:30-style
// zone (plain Truncate aligns to UTC).
func truncateLocal(t time.Time, d time.Duration) time.Time {
	_, offset := t.Zone()
	off := time.Duration(offset) * time.Second
	return t.Add(off).Truncate(d).Add(-off)
}

// Series aggregates the per-minute data into `count` sticks of width `bucket`,
// ending at the latest data point (anchorLatest) or now. count <= 0 means "as
// many sticks as needed to cover all data" (used for the All view).
func (s *Store) Series(bucket time.Duration, count int, anchorLatest bool) Series {
	if bucket <= 0 {
		bucket = time.Minute
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := Series{BucketSeconds: int64(bucket / time.Second)}
	if len(s.minutes) == 0 {
		return out
	}

	var maxMin, minMin int64 = math.MinInt64, math.MaxInt64
	for m := range s.minutes {
		if m > maxMin {
			maxMin = m
		}
		if m < minMin {
			minMin = m
		}
	}

	var anchorEnd time.Time
	if anchorLatest {
		anchorEnd = time.Unix(maxMin, 0).Add(time.Minute)
	} else {
		anchorEnd = time.Now()
	}
	// Align the anchor UP to a bucket boundary so the newest stick is whole.
	anchorEnd = truncateLocal(anchorEnd, bucket)
	if anchorEnd.Unix() <= maxMin {
		anchorEnd = anchorEnd.Add(bucket)
	}

	if count <= 0 { // cover everything, oldest data -> anchor
		span := anchorEnd.Sub(truncateLocal(time.Unix(minMin, 0), bucket))
		count = int(span/bucket) + 1
	}

	start := anchorEnd.Add(-bucket * time.Duration(count))
	buckets := make([]SeriesBucket, count)
	for i := range buckets {
		buckets[i].Start = start.Add(bucket * time.Duration(i)).Unix()
	}
	for m, b := range s.minutes {
		mt := time.Unix(m, 0)
		if mt.Before(start) || !mt.Before(anchorEnd) {
			continue
		}
		idx := int(mt.Sub(start) / bucket)
		if idx < 0 || idx >= count {
			continue
		}
		buckets[idx].Total += b.total
		buckets[idx].C1xx += b.class[1]
		buckets[idx].C2xx += b.class[2]
		buckets[idx].C3xx += b.class[3]
		buckets[idx].C4xx += b.class[4]
		buckets[idx].C5xx += b.class[5]
	}

	out.Anchor = anchorEnd.Unix()
	out.Start = start.Unix()
	out.Count = count
	out.Buckets = buckets
	return out
}

// LatestDataTime returns the timestamp of the most recent ingested record
// (minute-aligned), or the zero Time if nothing has been ingested yet. Alert
// evaluation anchors to this instead of wall-clock time.
func (s *Store) LatestDataTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var max int64 = math.MinInt64
	for m := range s.minutes {
		if m > max {
			max = m
		}
	}
	if max == math.MinInt64 {
		return time.Time{}
	}
	return time.Unix(max, 0)
}

// WindowStatusCount sums status-class counts across (end-window, end] for a
// site ("" = all sites combined). Used by threshold rules like "5 5xx in 2m".
func (s *Store) WindowStatusCount(site string, classes []int, window time.Duration, end time.Time) (matched, total int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := end.Add(-window).Truncate(time.Minute).Unix()
	endMin := end.Truncate(time.Minute).Unix()

	sum := func(mm map[int64]*classCounts) {
		for m, cc := range mm {
			if m <= cutoff || m > endMin {
				continue
			}
			total += cc.total
			for _, c := range classes {
				if c >= 0 && c < len(cc.class) {
					matched += cc.class[c]
				}
			}
		}
	}
	if site == "" {
		for _, mm := range s.siteMinutes {
			sum(mm)
		}
	} else if mm, ok := s.siteMinutes[site]; ok {
		sum(mm)
	}
	return
}

// WindowIPCounts sums per-IP request counts across (end-window, end]. Used by
// flood/scanner rules like "one IP makes >100 requests in 1m".
func (s *Store) WindowIPCounts(window time.Duration, end time.Time) map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := end.Add(-window).Truncate(time.Minute).Unix()
	endMin := end.Truncate(time.Minute).Unix()
	out := make(map[string]int64)
	for m, im := range s.ipMinutes {
		if m <= cutoff || m > endMin {
			continue
		}
		for ip, c := range im {
			out[ip] += c
		}
	}
	return out
}

// MinuteStat is one minute of status-class counts, used to build an anomaly
// baseline.
type MinuteStat struct {
	Minute int64
	Total  int64
	Class  [6]int64
}

// SiteMinuteSeries returns `count` consecutive one-minute buckets ending at
// end, oldest first, for a site ("" = all sites combined). Minutes with no
// traffic are included as zero-total entries; the caller decides whether to
// exclude them.
func (s *Store) SiteMinuteSeries(site string, count int, end time.Time) []MinuteStat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	endMin := end.Truncate(time.Minute).Unix()

	var mm map[int64]*classCounts
	if site == "" {
		mm = make(map[int64]*classCounts)
		for _, sm := range s.siteMinutes {
			for m, cc := range sm {
				agg := mm[m]
				if agg == nil {
					agg = &classCounts{}
					mm[m] = agg
				}
				agg.total += cc.total
				for i := range agg.class {
					agg.class[i] += cc.class[i]
				}
			}
		}
	} else {
		mm = s.siteMinutes[site]
	}

	out := make([]MinuteStat, count)
	for i := 0; i < count; i++ {
		minute := endMin - int64(count-1-i)*60
		out[i].Minute = minute
		if cc, ok := mm[minute]; ok {
			out[i].Total = cc.total
			out[i].Class = cc.class
		}
	}
	return out
}

// Overview is the top-level summary.
type Overview struct {
	Total          int64    `json:"total"`
	StatusClasses  [5]int64 `json:"status_classes"` // 1xx..5xx
	SuccessRate    float64  `json:"success_rate"`   // 2xx
	RedirectRate   float64  `json:"redirect_rate"`  // 3xx
	FailureRate    float64  `json:"failure_rate"`   // 4xx
	ErrorRate      float64  `json:"error_rate"`     // 5xx
	DistinctIPs    int      `json:"distinct_ips"`
	DistinctRoutes int      `json:"distinct_endpoints"`
	Sites          []string `json:"sites"`
}

// Overview aggregates all sites.
func (s *Store) Overview() Overview {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var all classCounts
	for _, sc := range s.sites {
		all.total += sc.total
		for i := range all.class {
			all.class[i] += sc.class[i]
		}
	}
	succ, redir, fail, er := all.Rates()
	sites := make([]string, 0, len(s.sites))
	for name := range s.sites {
		sites = append(sites, name)
	}
	sort.Strings(sites)
	return Overview{
		Total:          all.total,
		StatusClasses:  all.StatusClasses(),
		SuccessRate:    succ,
		RedirectRate:   redir,
		FailureRate:    fail,
		ErrorRate:      er,
		DistinctIPs:    len(s.ips),
		DistinctRoutes: len(s.endpoints),
		Sites:          sites,
	}
}

// IPView is an IP row for the API.
type IPView struct {
	IP           string    `json:"ip"`
	Total        int64     `json:"total"`
	SuccessRate  float64   `json:"success_rate"`
	RedirectRate float64   `json:"redirect_rate"`
	FailureRate  float64   `json:"failure_rate"`
	ErrorRate    float64   `json:"error_rate"`
	Endpoints    int       `json:"distinct_endpoints"`
	Sites        []string  `json:"sites"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// TopIPs returns the busiest IPs, highest volume first.
func (s *Store) TopIPs(limit int) []IPView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	views := make([]IPView, 0, len(s.ips))
	for _, ip := range s.ips {
		succ, redir, fail, er := ip.Rates()
		sites := make([]string, 0, len(ip.Sites))
		for name := range ip.Sites {
			sites = append(sites, name)
		}
		sort.Strings(sites)
		views = append(views, IPView{
			IP: ip.IP, Total: ip.total,
			SuccessRate: succ, RedirectRate: redir, FailureRate: fail, ErrorRate: er,
			Endpoints: len(ip.Endpoints), Sites: sites,
			FirstSeen: ip.First, LastSeen: ip.Last,
		})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Total > views[j].Total })
	return trim(views, limit)
}

// EndpointHit is one endpoint an IP called.
type EndpointHit struct {
	Endpoint string `json:"endpoint"`
	Hits     int64  `json:"hits"`
}

// IPDetail includes the endpoints an IP called.
type IPDetail struct {
	IPView
	CalledEndpoints []EndpointHit `json:"called_endpoints"`
}

// IPDetail returns one IP's full breakdown, or ok=false if unknown.
func (s *Store) IPDetail(addr string) (IPDetail, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ip, ok := s.ips[addr]
	if !ok {
		return IPDetail{}, false
	}
	succ, redir, fail, er := ip.Rates()
	sites := make([]string, 0, len(ip.Sites))
	for name := range ip.Sites {
		sites = append(sites, name)
	}
	sort.Strings(sites)
	eps := make([]EndpointHit, 0, len(ip.Endpoints))
	for e, h := range ip.Endpoints {
		eps = append(eps, EndpointHit{Endpoint: e, Hits: h})
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].Hits > eps[j].Hits })
	return IPDetail{
		IPView: IPView{
			IP: ip.IP, Total: ip.total,
			SuccessRate: succ, RedirectRate: redir, FailureRate: fail, ErrorRate: er,
			Endpoints: len(ip.Endpoints), Sites: sites,
			FirstSeen: ip.First, LastSeen: ip.Last,
		},
		CalledEndpoints: eps,
	}, true
}

// EndpointView is an endpoint row for the API.
type EndpointView struct {
	Site         string    `json:"site"`
	Method       string    `json:"method"`
	Endpoint     string    `json:"endpoint"`
	Total        int64     `json:"total"`
	SuccessRate  float64   `json:"success_rate"`
	RedirectRate float64   `json:"redirect_rate"`
	FailureRate  float64   `json:"failure_rate"`
	ErrorRate    float64   `json:"error_rate"`
	DistinctIPs  int       `json:"distinct_ips"`
	LastSeen     time.Time `json:"last_seen"`
}

// TopEndpoints returns the busiest endpoints, highest volume first.
func (s *Store) TopEndpoints(limit int) []EndpointView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	views := make([]EndpointView, 0, len(s.endpoints))
	for _, ep := range s.endpoints {
		succ, redir, fail, er := ep.Rates()
		views = append(views, EndpointView{
			Site: ep.Site, Method: ep.Method, Endpoint: ep.Template, Total: ep.total,
			SuccessRate: succ, RedirectRate: redir, FailureRate: fail, ErrorRate: er,
			DistinctIPs: len(ep.ips), LastSeen: ep.Last,
		})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Total > views[j].Total })
	return trim(views, limit)
}

func trim[T any](s []T, limit int) []T {
	if limit > 0 && len(s) > limit {
		return s[:limit]
	}
	return s
}
