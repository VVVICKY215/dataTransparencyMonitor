// Content-script bridge for fingerprinting detections.

(function() {
  'use strict';

  if (window.__DTM_DETECTOR_LOADED__) return;
  window.__DTM_DETECTOR_LOADED__ = true;

  console.log('[DTM] Content script loaded (message bridge)');

  // Listen for detections from the injected page script.
  window.addEventListener('message', function(event) {
    if (event.source !== window) return;

    if (!event.data || event.data.source !== 'DTM_INJECTED') return;

    console.log('[DTM] Received fingerprint detection:', event.data.payload);

    // Forward detections to the background worker.
    chrome.runtime.sendMessage({
      type: 'FINGERPRINT_DETECTED',
      data: event.data.payload
    }).then(response => {
      console.log('[DTM] Background response:', response);
    }).catch(err => {
      // Extension reloads can invalidate this context mid-message.
      if (!err.message.includes('Extension context invalidated')) {
        console.error('[DTM] Error sending message:', err);
      }
    });
  });

})();
