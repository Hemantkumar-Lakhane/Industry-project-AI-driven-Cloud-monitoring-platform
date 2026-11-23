/*
From Uiverse.io by dexter-st - https://uiverse.io/dexter-st/wicked-elephant-4
MIT License, Copyright (c) dexter-st
*/

import React from 'react';
import './WickedLoader.css';

export default function WickedLoader({
  text = 'Generating',
  scale = 1,
  className = '',
  style = {}
}) {
  const letters = Array.from(text);

  return (
    <div
      className={`wicked-loader-wrapper ${className}`}
      style={{
        transform: scale !== 1 ? `scale(${scale})` : undefined,
        transformOrigin: 'center center',
        ...style
      }}
      aria-label={text}
      role="status"
    >
      {letters.map((char, index) => {
        // Base delay formula matching dexter-st snippet
        const delay = 0.1 + index * 0.105;
        return (
          <span
            key={index}
            className="wicked-loader-letter"
            style={{ animationDelay: `${delay.toFixed(3)}s` }}
          >
            {char === ' ' ? '\u00A0' : char}
          </span>
        );
      })}

      <div className="wicked-loader" aria-hidden="true" />
    </div>
  );
}
