---
title: "Vimium Black Hint"
description: "Better than the default Vimium hint"
date: "2025-5-14"
---
```css
div > .vimiumHintMarker {
/* linkhint boxes */
background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,black),
  color-stop(100%,black));
border: 1px solid black;
}

div > .vimiumHintMarker span {
/* linkhint text */
color: white;
font-weight: bold;
font-size: 12px;
}

div > .vimiumHintMarker > .matchingCharacter {
}
```
