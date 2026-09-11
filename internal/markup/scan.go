package markup

import "strings"

// tag is one start tag, reduced to what examine() asks about.
type tag struct {
	name string
	attr map[string]string
}

// scanner walks markup looking for start tags.
//
// Not a parser. It builds no tree, tracks no nesting and corrects no mistakes,
// because a check needs the elements a page says it loads and nothing about how
// they relate. What it does have to get right is where a tag is *not*: inside a
// comment, and inside the text of a script or a style element. A scanner that
// got either wrong would report a commented-out reference as a live one, which
// is the false alarm that teaches a reader to skip the section.
type scanner struct {
	src string
	i   int
}

// rawText are the elements whose content is not markup.
//
// Everything between <script> and </script> is program text. A scanner that
// went on looking for "<" inside it would find the "<" in `if (a < b)` and read
// whatever followed as a tag — and a page whose script contains the string
// "http://" in a comparison would be reported as loading something over
// plaintext that it never loads.
var rawText = map[string]bool{
	"script":    true,
	"style":     true,
	"textarea":  true,
	"title":     true,
	"noscript":  true,
	"noembed":   true,
	"noframes":  true,
	"plaintext": true,
	"xmp":       true,
}

// next returns the next start tag, or false at the end of the input.
func (s *scanner) next() (tag, bool) {
	for {
		j := strings.IndexByte(s.src[s.i:], '<')
		if j < 0 {
			return tag{}, false
		}
		s.i += j + 1

		switch {
		case s.has("!--"):
			// A comment. Everything to "-->" is not markup, and a page with an
			// unterminated comment has no markup after it either — which is
			// what a browser does with one, so it is what this does.
			s.i += len("!--")
			s.skipTo("-->", len("-->"))
			continue

		case s.has("!"), s.has("?"):
			// A doctype, a processing instruction, or something malformed.
			// Nothing here is a subresource.
			s.skipTo(">", len(">"))
			continue

		case s.has("/"):
			// An end tag. Read past it; raw-text mode is left where it was
			// entered, in readTag, because that is where the element's name is
			// known.
			s.skipTo(">", len(">"))
			continue
		}

		name, attrs, selfClosing, ok := s.readTag()
		if !ok {
			return tag{}, false
		}
		if name == "" {
			continue
		}

		// A raw-text element's content is skipped whole, so nothing inside it
		// is read as markup. A self-closing spelling — <script/> — has no
		// content to skip, and treating it as though it did would swallow the
		// rest of the page.
		if rawText[name] && !selfClosing {
			s.skipToEndTag(name)
		}

		return tag{name: name, attr: attrs}, true
	}
}

// has reports whether the input at the cursor begins with prefix.
func (s *scanner) has(prefix string) bool {
	return strings.HasPrefix(s.src[s.i:], prefix)
}

// skipTo moves the cursor past the next occurrence of sep, or to the end of the
// input when there is none.
func (s *scanner) skipTo(sep string, width int) {
	j := strings.Index(s.src[s.i:], sep)
	if j < 0 {
		s.i = len(s.src)
		return
	}
	s.i += j + width
}

// skipToEndTag moves the cursor past the closing tag of a raw-text element.
//
// Matched case-insensitively on "</name", because "</SCRIPT>" closes a script
// and a scanner that missed it would read the whole rest of the page as program
// text and report nothing at all — the reassuring answer, arrived at by a bug.
func (s *scanner) skipToEndTag(name string) {
	want := "</" + name
	rest := s.src[s.i:]

	for off := 0; ; {
		j := indexFold(rest[off:], want)
		if j < 0 {
			s.i = len(s.src)
			return
		}
		at := off + j + len(want)

		// "</scriptx>" does not close a script. The character after the name
		// has to end it.
		if at < len(rest) && !isTagNameEnd(rest[at]) {
			off = off + j + 1
			continue
		}
		s.i += at
		return
	}
}

// readTag reads a start tag from just after its "<".
func (s *scanner) readTag() (name string, attrs map[string]string, selfClosing, ok bool) {
	start := s.i
	for s.i < len(s.src) && !isTagNameEnd(s.src[s.i]) {
		s.i++
	}
	if s.i == start {
		// "<" followed by something that cannot begin a name — a stray "<" in
		// text. Not a tag, and not an error either.
		return "", nil, false, true
	}
	name = strings.ToLower(s.src[start:s.i])

	attrs = map[string]string{}
	for {
		s.skipSpace()
		if s.i >= len(s.src) {
			return name, attrs, false, true
		}

		switch s.src[s.i] {
		case '>':
			s.i++
			return name, attrs, false, true
		case '/':
			s.i++
			if s.i < len(s.src) && s.src[s.i] == '>' {
				s.i++
				return name, attrs, true, true
			}
			continue
		}

		key, value := s.readAttr()
		if key == "" {
			// No progress is possible on this byte; step over it rather than
			// spin. An input that can stall a scanner is an input somebody
			// serves on purpose.
			s.i++
			continue
		}
		if _, taken := attrs[key]; !taken {
			// First wins, which is what a browser does with a repeated
			// attribute. A page carrying src twice is a page whose second src
			// no browser reads, so reporting it would be reporting something
			// that does not happen.
			attrs[key] = value
		}
	}
}

// readAttr reads one name, and its value where it has one.
func (s *scanner) readAttr() (key, value string) {
	start := s.i
	for s.i < len(s.src) && !isAttrNameEnd(s.src[s.i]) {
		s.i++
	}
	if s.i == start {
		return "", ""
	}
	key = strings.ToLower(s.src[start:s.i])

	s.skipSpace()
	if s.i >= len(s.src) || s.src[s.i] != '=' {
		// A valueless attribute, which is how "async" and "defer" are spelled.
		return key, ""
	}
	s.i++
	s.skipSpace()
	if s.i >= len(s.src) {
		return key, ""
	}

	switch q := s.src[s.i]; q {
	case '"', '\'':
		s.i++
		start = s.i
		for s.i < len(s.src) && s.src[s.i] != q {
			s.i++
		}
		value = s.src[start:s.i]
		if s.i < len(s.src) {
			s.i++
		}
	default:
		start = s.i
		for s.i < len(s.src) && !isUnquotedEnd(s.src[s.i]) {
			s.i++
		}
		value = s.src[start:s.i]
	}

	return key, value
}

func (s *scanner) skipSpace() {
	for s.i < len(s.src) && isSpace(s.src[s.i]) {
		s.i++
	}
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func isTagNameEnd(c byte) bool {
	return isSpace(c) || c == '>' || c == '/'
}

func isAttrNameEnd(c byte) bool {
	return isSpace(c) || c == '=' || c == '>' || c == '/'
}

func isUnquotedEnd(c byte) bool {
	return isSpace(c) || c == '>'
}

// indexFold is strings.Index without regard to case, over ASCII.
//
// Written rather than reached for, because strings.EqualFold over a sliding
// window is the shape that turns a large page into a quadratic read, and the
// page is chosen by whoever is being measured.
func indexFold(haystack, needle string) int {
	if len(needle) == 0 {
		return 0
	}
	first := lower(needle[0])
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if lower(haystack[i]) != first {
			continue
		}
		if equalFoldASCII(haystack[i:i+len(needle)], needle) {
			return i
		}
	}
	return -1
}

func equalFoldASCII(a, b string) bool {
	for i := 0; i < len(a); i++ {
		if lower(a[i]) != lower(b[i]) {
			return false
		}
	}
	return true
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
