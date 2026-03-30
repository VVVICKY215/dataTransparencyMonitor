/**
 * Data Transparency Monitor - Injected Script
 * 
 * 这个脚本被注入到页面的main world中
 * 可以直接访问和hook页面的JavaScript API
 * 
 * 检测目标：
 * 1. Canvas fingerprinting
 * 2. WebGL fingerprinting
 * 3. AudioContext fingerprinting
 * 4. Font enumeration
 */

(function() {
  'use strict';
  
  // 避免重复执行
  if (window.__DTM_DETECTOR_ACTIVE__) return;
  window.__DTM_DETECTOR_ACTIVE__ = true;
  
  // ============================================
  // 配置
  // ============================================
  
  const CONFIG = {
    // Canvas fingerprinting 检测阈值
    CANVAS_DATA_ACCESS_THRESHOLD: 1,  // 访问toDataURL/getImageData次数
    
    // WebGL fingerprinting 检测阈值
    WEBGL_PARAMETER_ACCESS_THRESHOLD: 5,  // 访问getParameter次数
    
    // AudioContext fingerprinting 检测阈值
    AUDIO_CONTEXT_THRESHOLD: 1,  // 创建并使用AudioContext
    
    // Font enumeration 检测阈值
    FONT_MEASURE_THRESHOLD: 10,  // measureText调用次数（降低以提高检测率）
    
    // 调试模式 - 开启以查看日志
    DEBUG: true
  };
  
  // 检测计数器
  const counters = {
    canvasDataAccess: 0,
    webglParameterAccess: 0,
    audioContextUsage: 0,
    fontMeasure: 0
  };
  
  // 已报告的检测类型（避免重复报告）
  const reported = {
    canvas: false,
    webgl: false,
    audio: false,
    font: false
  };
  
  // ============================================
  // 工具函数
  // ============================================
  
  function log(...args) {
    if (CONFIG.DEBUG) {
      console.log('[DTM Detector]', ...args);
    }
  }
  
  /**
   * 向content script发送检测结果
   */
  function reportDetection(type, details) {
    if (reported[type]) return;
    reported[type] = true;
    
    window.postMessage({
      source: 'DTM_INJECTED',
      payload: {
        type: type,
        details: details,
        url: window.location.href,
        timestamp: Date.now()
      }
    }, '*');
    
    log(`Reported ${type} fingerprinting:`, details);
  }
  
  /**
   * 安全地获取原始函数
   */
  function getOriginal(obj, prop) {
    const descriptor = Object.getOwnPropertyDescriptor(obj, prop);
    if (descriptor && descriptor.value) {
      return descriptor.value;
    }
    return obj[prop];
  }
  
  // ============================================
  // Canvas Fingerprinting 检测
  // ============================================
  
  function hookCanvasAPI() {
    // Hook toDataURL
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(...args) {
      counters.canvasDataAccess++;
      log('Canvas toDataURL called', { count: counters.canvasDataAccess });
      
      // 检查是否是fingerprinting行为
      // 通常fingerprinting会在小型canvas上调用
      if (counters.canvasDataAccess >= CONFIG.CANVAS_DATA_ACCESS_THRESHOLD) {
        const width = this.width;
        const height = this.height;
        
        // 排除大型canvas（可能是正常图像处理）
        if (width <= 500 && height <= 500) {
          reportDetection('canvas', {
            method: 'toDataURL',
            canvasSize: { width, height },
            callCount: counters.canvasDataAccess
          });
        }
      }
      
      return originalToDataURL.apply(this, args);
    };
    
    // Hook toBlob
    const originalToBlob = HTMLCanvasElement.prototype.toBlob;
    HTMLCanvasElement.prototype.toBlob = function(...args) {
      counters.canvasDataAccess++;
      log('Canvas toBlob called', { count: counters.canvasDataAccess });
      
      if (counters.canvasDataAccess >= CONFIG.CANVAS_DATA_ACCESS_THRESHOLD) {
        const width = this.width;
        const height = this.height;
        
        if (width <= 500 && height <= 500) {
          reportDetection('canvas', {
            method: 'toBlob',
            canvasSize: { width, height },
            callCount: counters.canvasDataAccess
          });
        }
      }
      
      return originalToBlob.apply(this, args);
    };
    
    // Hook getImageData
    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(...args) {
      counters.canvasDataAccess++;
      log('Canvas getImageData called', { count: counters.canvasDataAccess });
      
      if (counters.canvasDataAccess >= CONFIG.CANVAS_DATA_ACCESS_THRESHOLD) {
        reportDetection('canvas', {
          method: 'getImageData',
          callCount: counters.canvasDataAccess
        });
      }
      
      return originalGetImageData.apply(this, args);
    };
    
    log('Canvas API hooked');
  }
  
  // ============================================
  // WebGL Fingerprinting 检测
  // ============================================
  
  function hookWebGLAPI() {
    // 需要hook的参数（用于fingerprinting）
    const fingerprintParams = [
      'VENDOR',
      'RENDERER',
      'VERSION',
      'SHADING_LANGUAGE_VERSION',
      'MAX_TEXTURE_SIZE',
      'MAX_VERTEX_ATTRIBS',
      'MAX_VERTEX_UNIFORM_VECTORS',
      'MAX_VARYING_VECTORS',
      'MAX_COMBINED_TEXTURE_IMAGE_UNITS',
      'MAX_VERTEX_TEXTURE_IMAGE_UNITS',
      'MAX_TEXTURE_IMAGE_UNITS',
      'MAX_FRAGMENT_UNIFORM_VECTORS',
      'MAX_RENDERBUFFER_SIZE',
      'MAX_VIEWPORT_DIMS'
    ];
    
    const accessedParams = new Set();
    
    function hookContext(contextProto, contextName) {
      const originalGetParameter = contextProto.getParameter;
      
      contextProto.getParameter = function(pname) {
        counters.webglParameterAccess++;
        
        // 检查是否访问了fingerprinting相关参数
        for (const param of fingerprintParams) {
          if (this[param] === pname || this['UNMASKED_VENDOR_WEBGL'] === pname || this['UNMASKED_RENDERER_WEBGL'] === pname) {
            accessedParams.add(param);
            break;
          }
        }
        
        log(`${contextName}.getParameter called`, { 
          pname, 
          count: counters.webglParameterAccess,
          uniqueParams: accessedParams.size
        });
        
        // 如果访问了多个fingerprinting参数，报告检测
        if (accessedParams.size >= 3 || counters.webglParameterAccess >= CONFIG.WEBGL_PARAMETER_ACCESS_THRESHOLD) {
          reportDetection('webgl', {
            method: 'getParameter',
            accessedParams: Array.from(accessedParams),
            callCount: counters.webglParameterAccess
          });
        }
        
        return originalGetParameter.apply(this, arguments);
      };
      
      // Hook getExtension (用于获取WEBGL_debug_renderer_info)
      const originalGetExtension = contextProto.getExtension;
      contextProto.getExtension = function(name) {
        log(`${contextName}.getExtension called:`, name);
        
        if (name === 'WEBGL_debug_renderer_info') {
          reportDetection('webgl', {
            method: 'getExtension',
            extension: name,
            reason: 'Accessing GPU vendor/renderer info'
          });
        }
        
        return originalGetExtension.apply(this, arguments);
      };
    }
    
    // Hook WebGLRenderingContext
    if (typeof WebGLRenderingContext !== 'undefined') {
      hookContext(WebGLRenderingContext.prototype, 'WebGLRenderingContext');
    }
    
    // Hook WebGL2RenderingContext
    if (typeof WebGL2RenderingContext !== 'undefined') {
      hookContext(WebGL2RenderingContext.prototype, 'WebGL2RenderingContext');
    }
    
    log('WebGL API hooked');
  }
  
  // ============================================
  // AudioContext Fingerprinting 检测
  // ============================================
  
  function hookAudioAPI() {
    const audioContextUsage = {
      oscillatorCreated: false,
      analyserCreated: false,
      compressorCreated: false,
      destinationConnected: false
    };
    
    function checkAudioFingerprinting() {
      // 如果创建了oscillator和compressor/analyser，很可能是fingerprinting
      const suspiciousUsage = 
        (audioContextUsage.oscillatorCreated && audioContextUsage.compressorCreated) ||
        (audioContextUsage.oscillatorCreated && audioContextUsage.analyserCreated);
      
      if (suspiciousUsage) {
        counters.audioContextUsage++;
        
        if (counters.audioContextUsage >= CONFIG.AUDIO_CONTEXT_THRESHOLD) {
          reportDetection('audio', {
            usage: audioContextUsage,
            reason: 'AudioContext fingerprinting pattern detected'
          });
        }
      }
    }
    
    function hookAudioContext(AudioContextClass) {
      if (!AudioContextClass) return;
      
      const originalCreateOscillator = AudioContextClass.prototype.createOscillator;
      AudioContextClass.prototype.createOscillator = function() {
        audioContextUsage.oscillatorCreated = true;
        log('AudioContext.createOscillator called');
        checkAudioFingerprinting();
        return originalCreateOscillator.apply(this, arguments);
      };
      
      const originalCreateAnalyser = AudioContextClass.prototype.createAnalyser;
      AudioContextClass.prototype.createAnalyser = function() {
        audioContextUsage.analyserCreated = true;
        log('AudioContext.createAnalyser called');
        checkAudioFingerprinting();
        return originalCreateAnalyser.apply(this, arguments);
      };
      
      const originalCreateDynamicsCompressor = AudioContextClass.prototype.createDynamicsCompressor;
      AudioContextClass.prototype.createDynamicsCompressor = function() {
        audioContextUsage.compressorCreated = true;
        log('AudioContext.createDynamicsCompressor called');
        checkAudioFingerprinting();
        return originalCreateDynamicsCompressor.apply(this, arguments);
      };
    }
    
    // Hook AudioContext
    if (typeof AudioContext !== 'undefined') {
      hookAudioContext(AudioContext);
    }
    
    // Hook webkitAudioContext (Safari)
    if (typeof webkitAudioContext !== 'undefined') {
      hookAudioContext(webkitAudioContext);
    }
    
    // Hook OfflineAudioContext
    if (typeof OfflineAudioContext !== 'undefined') {
      hookAudioContext(OfflineAudioContext);
    }
    
    log('Audio API hooked');
  }
  
  // ============================================
  // Font Enumeration 检测
  // ============================================
  
  function hookFontAPI() {
    const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
    const measuredFonts = new Set();
    
    CanvasRenderingContext2D.prototype.measureText = function(text) {
      counters.fontMeasure++;
      
      // 提取当前设置的字体
      const currentFont = this.font;
      if (currentFont) {
        measuredFonts.add(currentFont);
      }
      
      // 如果短时间内测量了大量不同字体，可能是font enumeration
      if (measuredFonts.size >= CONFIG.FONT_MEASURE_THRESHOLD) {
        log('Font enumeration detected', { 
          fontCount: measuredFonts.size,
          callCount: counters.fontMeasure
        });
        
        reportDetection('font', {
          method: 'measureText',
          uniqueFonts: measuredFonts.size,
          callCount: counters.fontMeasure,
          reason: 'Large number of font measurements'
        });
      }
      
      return originalMeasureText.apply(this, arguments);
    };
    
    log('Font API hooked');
  }
  
  // ============================================
  // 初始化
  // ============================================
  
  function init() {
    try {
      console.log('[DTM Detector] Initializing fingerprint detection...');
      hookCanvasAPI();
      hookWebGLAPI();
      hookAudioAPI();
      hookFontAPI();
      
      console.log('[DTM Detector] All APIs hooked successfully');
    } catch (error) {
      console.error('[DTM Detector] Error during initialization:', error);
    }
  }
  
  // 立即执行
  init();
  
})();
