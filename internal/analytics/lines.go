package analytics

import (
	"bufio"
	"io"
	"strings"
)

// readLines reads r, calling fn for each newline-terminated line (with the
// trailing "\n"/"\r\n" stripped). Unlike bufio.Scanner (used here previously),
// there is no hard per-line size limit -- an unusually long or torn/garbled
// line is read in full and handed to fn as one line (which Parse harmlessly
// rejects as unrecognizable, same as any other malformed line) rather than
// aborting the entire read and silently discarding everything after it.
//
// This matters on a real busy nginx box: two workers writing large log lines
// (e.g. a request URL carrying multi-KB embedded tokens) to the same file can
// have their writes interleave -- Linux only guarantees a single write(2) call
// is atomic, not a logical log line split across several writes when it
// exceeds nginx's internal log buffer. The result is an occasional garbled
// "line" far longer than normal. bufio.Scanner's default token-size cap turns
// that into a hard, silent, PERMANENT stall (see Tailer.drain's prior
// behavior); ReadString just reads however much is actually there.
//
// Tradeoff, accepted deliberately: since ReadString grows its buffer until it
// finds the delimiter, a pathological input with no newline for a very long
// stretch would grow memory to match before giving up. Reading a locally
// produced nginx log (not arbitrary attacker-controlled network input), the
// realistic worst case is a handful of torn concurrent writes glued together
// -- bounded by how much a handful of large lines can add up to, not
// unbounded -- so no artificial cap is imposed here; that would just
// reproduce the same class of failure in a different guise.
//
// Returns the number of bytes consumed by complete (newline-terminated)
// lines, any trailing unterminated fragment (e.g. a line nginx hasn't
// finished writing yet) separately -- uncounted and NOT passed to fn, since
// it's the caller's job to decide whether to process it anyway (a one-shot
// batch read: yes, nothing else will ever see it) or leave it alone (live
// tailing: yes, there's a next poll that will see it complete) -- and any
// real (non-EOF) read error.
func readLines(r io.Reader, fn func(line string)) (consumed int64, partial string, err error) {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, rerr := br.ReadString('\n')
		complete := len(line) > 0 && line[len(line)-1] == '\n'
		if complete {
			consumed += int64(len(line))
			fn(strings.TrimRight(line, "\r\n"))
		}
		if rerr != nil {
			if rerr == io.EOF {
				if !complete {
					partial = line
				}
				return consumed, partial, nil
			}
			return consumed, partial, rerr
		}
	}
}
