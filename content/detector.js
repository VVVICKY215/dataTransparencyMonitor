/**
 * Data Transparency Monitor - Content Script (Detector)
 * 
 * 职责：
 * 监听来自injected.js（MAIN world）的消息，转发给background script
 */

(function() {
  'use strict';
  
  // 避免重复注入
  if (window.__DTM_DETECTOR_LOADED__) return;
  window.__DTM_DETECTOR_LOADED__ = true;
  
  console.log('[DTM] Content script loaded (message bridge)');
  
  /**
   * 监听来自injected script的消息
   */
  window.addEventListener('message', function(event) {
    // 只接受来自同一窗口的消息
    if (event.source !== window) return;
    
    // 检查消息格式
    if (!event.data || event.data.source !== 'DTM_INJECTED') return;
    
    console.log('[DTM] Received fingerprint detection:', event.data.payload);
    
    // 转发给background script
    chrome.runtime.sendMessage({
      type: 'FINGERPRINT_DETECTED',
      data: event.data.payload
    }).then(response => {
      console.log('[DTM] Background response:', response);
    }).catch(err => {
      // 忽略扩展上下文失效的错误
      if (!err.message.includes('Extension context invalidated')) {
        console.error('[DTM] Error sending message:', err);
      }
    });
  });
  
})();
