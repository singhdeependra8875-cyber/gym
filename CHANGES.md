# GymDesk client-ready revision 2

This revision is a full bug/security pass over the previous client-ready build.

## Fixed
- Fixed modal click handling so Add Member, Save, Cancel, Edit, Renew and Delete buttons actually work.
- Fixed Edit/Renew modal state handling.
- Fixed plan-price updates when changing a plan in the renewal form.
- Normalized saved phone numbers to exactly 10 digits.
- Payment history now records the actual payment date (today), while membership start date remains separate.
- Backup restore is transactional: an invalid/failed restore no longer replaces the current in-memory data.
- Added strong client-side backup validation and matching server-side validation.
- Added validation for unique member/plan IDs, referenced plans, dates, payment modes, amounts and country code.
- Fixed unsafe dynamic IDs/attributes by escaping rendered data.
- Added stricter date validation so impossible calendar dates are rejected.
- Improved logout so it does not clear the page until the final save succeeds.
- Added a save-in-progress warning before closing/reloading the page.
- Added cache-control headers for API responses and additional HTTP security headers.
- Enabled SQLite WAL mode and a busy timeout for more reliable local persistence.
- Validates stored database data before returning it to the browser.
- Improved import/export feedback and cleanup.
- Added change-event handling for selects, making plan/price updates reliable across browsers.

## Architecture notes
- Still a single-owner app with one password and one SQLite database, not a multi-user SaaS.
- For deployment, use HTTPS and persistent disk storage for the SQLite database.
- The app keeps 30 daily server-side snapshots and also supports manual JSON backup/restore.
