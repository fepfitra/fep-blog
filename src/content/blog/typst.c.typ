#import "@preview/mannot:0.3.1": *
#import "../../typst-theme.c.typ": project
#show: project

#let desc = [$oo$ fun with `math`]
#metadata(
  (
    title: "Test page",
    author: "Neko",
    description: "lmaoo",
    date: "2025-6-4",
  ),
)<frontmatter>

$
  markhl(x) + markhl(y, color: #blue, tag: #<tag1>)
  #annot(<tag1>)[Annotation]
$

$
  e = m c^2
$
== anu

$
  e = m c^2
$
```python
import math
def test(x):
    return math.sqrt(x)
```

== anu
== anuaaa

this inline math $dot(e) = m c^2$ is cool
