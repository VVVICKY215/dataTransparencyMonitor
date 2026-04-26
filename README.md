# Data Transparency Monitor
Data Transparency Monitor (DTM) is a Chrome browser extension developed as a research prototype for a university final-year project. It observes web-tracking-related signals and presents a real-time, context-aware privacy risk estimate to the user.

DTM does not block requests. Instead, it aims to make tracking activity more visible and understandable by showing an estimated Low, Medium, or High risk level based on observable page activity.

## What it does

DTM observes four families of signals associated with web tracking:

- **Browser fingerprinting** — Canvas, WebGL, AudioContext, and
  font-enumeration patterns.
- **Cookie syncing** — redirect chains carrying user-identifier
  parameters between known sync services.
- **CNAME-cloaked tracking** — requests to known endpoints that
  disguise third-party trackers as first-party subdomains.
- **Third-party trackers** — requests matched against curated
  community tracker lists (EasyPrivacy, Disconnect, Tracker Radar).

These signals feed a four-dimensional **Contextual Risk Engine**
that combines tracker capability, site sensitivity, tracking
frequency, and tracker-category context into a single estimate,
banded as Low / Medium / High. The estimate updates continuously
as new signals are observed—including the moment a user accepts
a cookie banner.

## Installation

1. Download the latest release zip from the
   [Releases](https://github.com/VVVICKY215/dataTransparencyMonitor/releases)
   page.
2. Unzip the downloaded folder.
3. Open Chrome and go to `chrome://extensions`.
4. Enable **Developer Mode** using the toggle in the top-right
   corner.
5. Click **Load unpacked** and select the unzipped folder.
6. The DTM icon will appear in the Chrome toolbar. Click it on any
   page to view the current tracking-risk estimate.

> **For user-study participants**: please follow the installation
> walkthrough in the survey, which also asks you to enable the
> *Allow in Incognito* option for one of the tasks.

## Academic context

This extension was designed and evaluated as the artefact for a
BEng Electronic Engineering final-year project examining how
real-time, context-aware transparency affects users' perception
of web tracking. The evaluation involved a remote, mixed-methods
user study with 22 participants completing three browsing tasks.

The study was approved by the Faculty Research Ethics Committee,
University of Southampton (ERGO/FEPS/109284).

## Author

Yuchen Zhao  
University of Southampton  
Supervisor: Dr Weijia He · Examiner: Dr Haiming Liu