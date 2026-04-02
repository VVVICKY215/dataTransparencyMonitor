(function() {
  'use strict';

  if (window.__DTM_DETECTOR_ACTIVE__) return;
  window.__DTM_DETECTOR_ACTIVE__ = true;

  const CONFIG = {
    CANVAS_DATA_ACCESS_THRESHOLD: 2,
    WEBGL_PARAMETER_ACCESS_THRESHOLD: 8,
    AUDIO_CONTEXT_THRESHOLD: 2,
    FONT_MEASURE_THRESHOLD: 16,
    DEBUG: false
  };

  const counters = {
    canvasDataAccess: 0,
    webglParameterAccess: 0,
    audioContextUsage: 0,
    fontMeasure: 0
  };

  const reported = {
    canvas: false,
    webgl: false,
    audio: false,
    font: false
  };

  function log(...args) {
    if (CONFIG.DEBUG) {
      console.log('[DTM Detector]', ...args);
    }
  }

  function reportDetection(type, details) {
    if (reported[type]) return;
    reported[type] = true;

    window.postMessage({
      source: 'DTM_INJECTED',
      payload: {
        type,
        details,
        url: window.location.href,
        timestamp: Date.now()
      }
    }, '*');

    log(`Reported ${type} fingerprinting`, details);
  }

  function hookCanvasAPI() {
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(...args) {
      counters.canvasDataAccess++;
      const width = this.width;
      const height = this.height;

      if (counters.canvasDataAccess >= CONFIG.CANVAS_DATA_ACCESS_THRESHOLD && width > 0 && height > 0 && width <= 400 && height <= 400) {
        reportDetection('canvas', {
          method: 'toDataURL',
          canvasSize: { width, height },
          callCount: counters.canvasDataAccess
        });
      }

      return originalToDataURL.apply(this, args);
    };

    const originalToBlob = HTMLCanvasElement.prototype.toBlob;
    HTMLCanvasElement.prototype.toBlob = function(...args) {
      counters.canvasDataAccess++;
      const width = this.width;
      const height = this.height;

      if (counters.canvasDataAccess >= CONFIG.CANVAS_DATA_ACCESS_THRESHOLD && width > 0 && height > 0 && width <= 400 && height <= 400) {
        reportDetection('canvas', {
          method: 'toBlob',
          canvasSize: { width, height },
          callCount: counters.canvasDataAccess
        });
      }

      return originalToBlob.apply(this, args);
    };

    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(...args) {
      counters.canvasDataAccess++;
      const canvas = this.canvas;
      const width = canvas?.width || 0;
      const height = canvas?.height || 0;

      if (counters.canvasDataAccess >= CONFIG.CANVAS_DATA_ACCESS_THRESHOLD && width > 0 && height > 0 && width <= 400 && height <= 400) {
        reportDetection('canvas', {
          method: 'getImageData',
          canvasSize: { width, height },
          callCount: counters.canvasDataAccess
        });
      }

      return originalGetImageData.apply(this, args);
    };
  }

  function hookWebGLAPI() {
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

    function hookContext(contextProto) {
      const originalGetParameter = contextProto.getParameter;
      contextProto.getParameter = function(pname) {
        counters.webglParameterAccess++;

        for (const param of fingerprintParams) {
          if (this[param] === pname || this.UNMASKED_VENDOR_WEBGL === pname || this.UNMASKED_RENDERER_WEBGL === pname) {
            accessedParams.add(param);
            break;
          }
        }

        if (accessedParams.size >= 4 || counters.webglParameterAccess >= CONFIG.WEBGL_PARAMETER_ACCESS_THRESHOLD) {
          reportDetection('webgl', {
            method: 'getParameter',
            accessedParams: Array.from(accessedParams),
            callCount: counters.webglParameterAccess
          });
        }

        return originalGetParameter.apply(this, arguments);
      };

      const originalGetExtension = contextProto.getExtension;
      contextProto.getExtension = function(name) {
        if (name === 'WEBGL_debug_renderer_info') {
          reportDetection('webgl', {
            method: 'getExtension',
            extension: name,
            reason: 'Accessing GPU vendor or renderer information'
          });
        }

        return originalGetExtension.apply(this, arguments);
      };
    }

    if (typeof WebGLRenderingContext !== 'undefined') {
      hookContext(WebGLRenderingContext.prototype);
    }

    if (typeof WebGL2RenderingContext !== 'undefined') {
      hookContext(WebGL2RenderingContext.prototype);
    }
  }

  function hookAudioAPI() {
    const audioContextUsage = {
      oscillatorCreated: false,
      analyserCreated: false,
      compressorCreated: false
    };

    function checkAudioFingerprinting() {
      const suspiciousUsage =
        (audioContextUsage.oscillatorCreated && audioContextUsage.compressorCreated) ||
        (audioContextUsage.oscillatorCreated && audioContextUsage.analyserCreated);

      if (suspiciousUsage) {
        counters.audioContextUsage++;
        if (counters.audioContextUsage >= CONFIG.AUDIO_CONTEXT_THRESHOLD) {
          reportDetection('audio', {
            usage: audioContextUsage,
            reason: 'Audio API usage resembles a fingerprinting pattern'
          });
        }
      }
    }

    function hookAudioContext(AudioContextClass) {
      if (!AudioContextClass) return;

      const originalCreateOscillator = AudioContextClass.prototype.createOscillator;
      AudioContextClass.prototype.createOscillator = function() {
        audioContextUsage.oscillatorCreated = true;
        checkAudioFingerprinting();
        return originalCreateOscillator.apply(this, arguments);
      };

      const originalCreateAnalyser = AudioContextClass.prototype.createAnalyser;
      AudioContextClass.prototype.createAnalyser = function() {
        audioContextUsage.analyserCreated = true;
        checkAudioFingerprinting();
        return originalCreateAnalyser.apply(this, arguments);
      };

      const originalCreateDynamicsCompressor = AudioContextClass.prototype.createDynamicsCompressor;
      AudioContextClass.prototype.createDynamicsCompressor = function() {
        audioContextUsage.compressorCreated = true;
        checkAudioFingerprinting();
        return originalCreateDynamicsCompressor.apply(this, arguments);
      };
    }

    if (typeof AudioContext !== 'undefined') {
      hookAudioContext(AudioContext);
    }

    if (typeof webkitAudioContext !== 'undefined') {
      hookAudioContext(webkitAudioContext);
    }

    if (typeof OfflineAudioContext !== 'undefined') {
      hookAudioContext(OfflineAudioContext);
    }
  }

  function hookFontAPI() {
    const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
    const measuredFonts = new Set();

    CanvasRenderingContext2D.prototype.measureText = function(text) {
      counters.fontMeasure++;
      const currentFont = this.font;

      if (currentFont) {
        measuredFonts.add(currentFont);
      }

      if (measuredFonts.size >= CONFIG.FONT_MEASURE_THRESHOLD && counters.fontMeasure >= CONFIG.FONT_MEASURE_THRESHOLD) {
        reportDetection('font', {
          method: 'measureText',
          uniqueFonts: measuredFonts.size,
          callCount: counters.fontMeasure,
          reason: 'A large number of font measurements were observed'
        });
      }

      return originalMeasureText.apply(this, arguments);
    };
  }

  function init() {
    try {
      hookCanvasAPI();
      hookWebGLAPI();
      hookAudioAPI();
      hookFontAPI();
      log('All hooks initialized');
    } catch (error) {
      console.error('[DTM Detector] Initialization error:', error);
    }
  }

  init();
})();
