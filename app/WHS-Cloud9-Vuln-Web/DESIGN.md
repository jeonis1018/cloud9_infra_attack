---
version: alpha
colors:
  primary: "#176b66"
  primary-dark: "#104d4a"
  accent: "#e6d34d"
  brown: "#563d2e"
  paper: "#f4f2e9"
  surface: "#fffefa"
  text: "#292b26"
  muted: "#716f65"
  line: "#d8d4c7"
typography:
  sans:
    fontFamily: "Pretendard, Apple SD Gothic Neo, Malgun Gothic, sans-serif"
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace"
rounded:
  control: "0px"
  surface: "0px"
spacing:
  page-gutter: "24px"
  section-gap: "24px"
components:
  button:
    radius: "0px"
    height: "42px"
  feature-dialog:
    radius: "0px"
    max-width: "740px"
---

## Overview

WHS-Cloud9-Vuln-Web is a Korean team security-lab workspace. Its main job is to let an authorized learner sign in, choose a lab, and run a small exercise. Treat it as a practical product screen, not a marketing landing page.

The visual reference is a team field station: a dark green-blue wayfinding bar, warm paper-like work surface, and sulfur-yellow markers that feel like labels on a shared lab bench. The recognizable signature is the green-blue header with a yellow rail and small, purposeful yellow markers. Let the exercises and their results carry the attention.

Runtime tokens are owned by `public/style.css`; this file records the accepted values and intent. Keep the CSS variables and this document aligned in the same change.

## Colors

Use green-blue (`--green-blue`) for primary actions and navigation cues, dark green (`--green-dark`) for the top bar, sulfur yellow (`--yellow`) for a few active markers and focus, and Van Dyke brown (`--brown`) for supporting emphasis and terminal output. Warm paper is the page canvas; white is for forms and dialogs. Muted text is still readable body copy, not decoration. Do not use gradients or spread yellow across large surfaces.

## Typography

Use the system Korean sans stack for headings and interface copy. Give headings and action labels clear weight; keep explanations and metadata regular so every line does not shout. Use the mono stack only for short lab labels and command output. Preserve readable Korean line height and allow long filenames, URLs, and output to wrap.

## Layout

Keep the top navigation visible above the main content. Center the desktop work area at a readable maximum width; collapse the sign-in and lab launcher to one column on small screens. Feature tools open in the existing dialog. Let forms and command results scroll inside that dialog without covering its close control.

## Elevation & Depth

Use borders and background tone to separate work areas. Avoid floating-card shadows and blurred glass. A restrained, offset dialog shadow may mark the active layer; the toast sits above it.

## Shapes

Controls, cards, and dialog use square corners, matching the current utility-focused interface. Reserve circles for user avatars and status dots only. Use thin rules for grouping; avoid repeating thick colored strips on every panel.

## Components

### Foundational visual states

Buttons and links show a clear hover state and a high-contrast keyboard focus ring. Disabled controls remain visibly muted. Reduced-motion preferences suppress transitions. Global scrollbars use the page palette, with forced-colors mode returning to system colors.

### Buttons and actions

Green-blue filled buttons are the main action; bordered white buttons are secondary. Keep button labels short and use the same intent consistently across the dialog.

### Navigation and data display

The dark header is the single primary navigation surface. The four lab launchers are a quiet ruled list/grid with concise numbers, titles, and descriptions rather than elevated generic cards.

### Forms and overlays

Fields use square borders and visible labels. Upload target uses a dashed outline as the specific drop cue. The native feature dialog is constrained to the viewport and scrolls when content is long; toast feedback remains above it.

### Iconography

Use the existing compact text/monospace marks and the WhiteHat School logo. Do not introduce a second icon style without a product need.

### Motion

Use brief color changes for hover feedback only. Respect reduced motion; animation is not a decoration layer.

## Do's and Don'ts

- **Do:** Keep the agreed sulfur-yellow, Van Dyke brown, green-blue, and white palette.
- **Do:** Give Korean headings decisive weight and keep explanatory text calmer.
- **Don't:** Put a gradient, oversized shadow, or decorative badge on every component.
- **Don't:** Make every sentence bold; use type scale and spacing to establish hierarchy.


## Member list and file deletion

The member menu uses the existing feature dialog, notification helper, and refresh action. Show only name and join date, formatted in Korean with Asia/Seoul time. Keep loading, empty, and retry states in the status region. File deletion reuses the secondary button beside execution, confirms the filename with the native confirmation dialog, and refreshes the list only after success. Ownership is enforced by the server session and S3 user prefix.
