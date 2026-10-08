import React from "react";
import type { CrtVariant } from "../shaders/crt/crtScreens";

export interface CrtConfig {
  speed: number;
  typeSpeed: number;
  motion: number;
  hue: number;
  saturation: number;
  brightness: number;
  opacity: number;
  variant: CrtVariant;
}

interface CrtConfigModalProps {
  config: CrtConfig;
  onChange: (cfg: CrtConfig) => void;
  onClose: () => void;
}

export const CrtConfigModal: React.FC<CrtConfigModalProps> = ({
  config,
  onChange,
  onClose,
}) => {
  const resetDefaults = () => {
    onChange({
      speed: 1.0,
      typeSpeed: 1.0,
      motion: 1.0,
      hue: 0,
      saturation: 1.0,
      brightness: 1.0,
      opacity: 1.0,
      variant: "terminal",
    });
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title">📺 CRT WEBGL SHADER & PHOSPHOR DISPLAY CONFIG</div>
          <button className="btn-close" onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="modal-body">
          <div className="slider-row">
            <label>Phosphor Hue Shift ({config.hue}°):</label>
            <input
              type="range"
              min="-180"
              max="180"
              step="5"
              value={config.hue}
              onChange={(e) => onChange({ ...config, hue: parseFloat(e.target.value) })}
            />
          </div>

          <div className="slider-row">
            <label>CRT Brightness & Bloom ({config.brightness.toFixed(2)}x):</label>
            <input
              type="range"
              min="0.4"
              max="2.0"
              step="0.05"
              value={config.brightness}
              onChange={(e) => onChange({ ...config, brightness: parseFloat(e.target.value) })}
            />
          </div>

          <div className="slider-row">
            <label>Scanline Motion & Grain ({config.motion.toFixed(2)}x):</label>
            <input
              type="range"
              min="0.0"
              max="2.5"
              step="0.1"
              value={config.motion}
              onChange={(e) => onChange({ ...config, motion: parseFloat(e.target.value) })}
            />
          </div>

          <div className="slider-row">
            <label>Typing Animation Rate ({config.typeSpeed.toFixed(2)}x):</label>
            <input
              type="range"
              min="0.2"
              max="3.0"
              step="0.1"
              value={config.typeSpeed}
              onChange={(e) => onChange({ ...config, typeSpeed: parseFloat(e.target.value) })}
            />
          </div>

          <div className="slider-row">
            <label>Color Saturation ({config.saturation.toFixed(2)}x):</label>
            <input
              type="range"
              min="0.0"
              max="2.0"
              step="0.05"
              value={config.saturation}
              onChange={(e) => onChange({ ...config, saturation: parseFloat(e.target.value) })}
            />
          </div>

          <div className="slider-row">
            <label>Background Opacity ({Math.round(config.opacity * 100)}%):</label>
            <input
              type="range"
              min="0.1"
              max="1.0"
              step="0.05"
              value={config.opacity}
              onChange={(e) => onChange({ ...config, opacity: parseFloat(e.target.value) })}
            />
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn-action btn-subtle" onClick={resetDefaults}>
            🔄 RESET TO FACTORY
          </button>
          <button className="btn-action btn-primary" onClick={onClose}>
            ✓ APPLY & CLOSE
          </button>
        </div>
      </div>
    </div>
  );
};
