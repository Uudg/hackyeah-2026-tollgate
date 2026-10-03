# MetricTile

A labelled number for the overview and the stage screen: what is measured, the value with its unit, and one line of context.

- The consumer provides label, value, unit and the context line. Units go in `<small>`, never glued to the number.
- Add a `tg-bar` for budget use; switch it to `is-hot` at 90 % or more.
- Only real measurements. A demo value is labelled "example".
