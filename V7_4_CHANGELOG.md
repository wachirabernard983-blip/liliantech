# Version 7.4

- Fixed the TheoremReach **Continue** action for surveys already marked `in_progress`.
- Existing TheoremReach activity now returns a fresh authenticated entry URL so the survey opens instead of silently doing nothing.
- Existing live survey starts also return their provider URL when available.
- No new Render environment variables are required.


## Version 7.5

- Removed the TheoremReach hosted Reward Center from the LilianTech survey inventory so users are not presented with TheoremReach login/branding as the default survey experience.
- Added an optional `THEOREMREACH_SURVEYS_API_URL` native-inventory adapter. The endpoint is deliberately configurable because the official Surveys API endpoint/schema must come from TheoremReach; no undocumented endpoint is guessed.
- Kept the verified TheoremReach server-side reward callback and HMAC validation.
- Strengthened dashboard mobile/desktop overflow handling and added Terms of Service / Privacy Policy footer links.
