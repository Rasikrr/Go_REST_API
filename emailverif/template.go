package emailverif

import "fmt"

func Template(name string, url string) string {
	temp := `<h1>Go API Email Verification </h2>
		<p>Hello, %s! Please verify your <a href=%s>account</a></p>`
	return fmt.Sprintf(temp, name, url)
}
