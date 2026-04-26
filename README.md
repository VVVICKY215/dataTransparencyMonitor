# Data Transparency Monitor

Data Transparency Monitor (DTM) is a Chrome extension built as a research prototype for a final-year university project. It watches for signals linked to web tracking and shows a live privacy risk estimate for the page you are visiting.

DTM is a transparency tool, not a blocker. It does not stop network requests or change how a page behaves. Instead, it helps make tracking activity easier to see by showing an estimated Low, Medium, or High risk level based on activity the extension can observe in the browser.

## What it does

DTM looks for four types of tracking signals:

- **Browser fingerprinting** - use of Canvas, WebGL, AudioContext, and
  font-enumeration patterns.
- **Cookie syncing** - redirect chains that carry user-identifier
  parameters between known syncing services.
- **CNAME-cloaked tracking** - requests to known endpoints that make
  third-party trackers appear as first-party subdomains.
- **Third-party trackers** - requests matched against community tracker
  lists, including EasyPrivacy, Disconnect, and Tracker Radar.

These signals are passed to the **Contextual Risk Engine**. The engine
combines tracker capability, site sensitivity, tracking frequency, and
tracker category into one risk estimate. The estimate is shown as Low,
Medium, or High and updates as the page changes, including after a user
accepts a cookie banner.

## Installation

1. Download the latest release ZIP from the
   [Releases](https://github.com/VVVICKY215/dataTransparencyMonitor/releases)
   page.
2. Unzip the downloaded folder.
3. Open Chrome and go to `chrome://extensions`.
4. Enable **Developer mode** using the toggle in the top-right
   corner.
5. Click **Load unpacked** and select the unzipped folder.
6. The DTM icon will appear in the Chrome toolbar. Click it on any
   page to view the current tracking risk estimate.

> **For user-study participants**: please follow the installation
> walkthrough in the survey, which also asks you to enable the
> *Allow in Incognito* option for one of the tasks.

## Academic context

This extension was designed and evaluated as the artefact for a
BEng Electronic Engineering final-year project at the University of
Southampton. The project examined whether real-time, context-aware
privacy information changes how users understand web tracking. The
evaluation used a remote, mixed-methods user study with 22 participants,
who completed three browsing tasks.

The study was approved by the Faculty Research Ethics Committee,
University of Southampton (ERGO/FEPS/109284).

## Author

Yuchen Zhao  
University of Southampton  
Supervisor: Dr Weijia He · Examiner: Dr Haiming Liu
