import React, { useRef } from 'react';
import './SpotlightCard.css';

export default function SpotlightCard({
  children,
  className = '',
  spotlightColor = 'rgba(249, 115, 22, 0.15)',
  style = {},
  onClick
}) {
  const cardRef = useRef(null);

  const handleMouseMove = (e) => {
    if (!cardRef.current) return;
    const rect = cardRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    cardRef.current.style.setProperty('--mouse-x', `${x}px`);
    cardRef.current.style.setProperty('--mouse-y', `${y}px`);
  };

  return (
    <div
      ref={cardRef}
      onMouseMove={handleMouseMove}
      onClick={onClick}
      className={`spotlight-card ${className}`}
      style={{
        '--spotlight-color': spotlightColor,
        ...style
      }}
    >
      <div className="spotlight-card-content">{children}</div>
    </div>
  );
}
