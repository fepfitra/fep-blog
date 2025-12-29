#let project(body) = {
  show math.equation: it => {
    let r = if it.block { "math" } else { "inline-math" }
    let styled_it = if it.block { text(size: 1.5em, it) } else { text(size: 1.2em, it) }
    [
      #html.elem("span", attrs: (role: r, class: "typst-math-light"), html.frame(styled_it))
      #html.elem("span", attrs: (role: r, class: "typst-math-dark"), html.frame({
        set text(fill: white)
        styled_it
      }))
    ]
  }
  body
}
