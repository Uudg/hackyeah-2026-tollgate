# StageScreen

The `/live` page for the projector: readable from the back of a hall, Night theme only, no scrolling.

- Left column: posture score, blocked in the last 5 minutes, one budget. Right: the gate (arm up when the latest decision is allow, down on block) and the newest decisions, newest first, at most four rows.
- All text 18 px or larger; rule ids at 20 px+ in `data`.
- Driven by the live event stream; values shown here are examples.
- Motion follows the README: arm lifts on allow, drops with one short shake on block, the canary tips off on kill.
