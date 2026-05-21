import { useState, useEffect, useRef } from 'react';

const CHARACTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=';

export interface SkyperOptions {
  duration?: number;
  fps?: number;
  delay?: number;
}

export const useSkyper = (
  targetText: string,
  options: SkyperOptions = {}
) => {
  const { duration = 1000, fps = 30, delay = 0 } = options;
  const [displayedText, setDisplayedText] = useState(
    targetText.replace(/[a-zA-Z0-9]/g, '-')
  );
  const isDecoding = useRef(false);

  const startDecoding = () => {
    if (isDecoding.current) return;
    isDecoding.current = true;

    let frame = 0;
    const totalFrames = (duration / 1000) * fps;
    const interval = 1000 / fps;
    
    setTimeout(() => {
      const timer = setInterval(() => {
        frame++;
        
        let newText = '';
        const progress = frame / totalFrames;
        
        for (let i = 0; i < targetText.length; i++) {
          if (targetText[i] === ' ') {
            newText += ' ';
            continue;
          }
          
          // Characters reveal gradually from left to right based on progress
          const revealThreshold = i / targetText.length;
          
          if (progress >= revealThreshold + 0.1) {
            newText += targetText[i];
          } else if (progress >= revealThreshold) {
            // Actively scrambling
            newText += CHARACTERS[Math.floor(Math.random() * CHARACTERS.length)];
          } else {
            // Still encrypted
            newText += '-';
          }
        }
        
        setDisplayedText(newText);
        
        if (frame >= totalFrames) {
          clearInterval(timer);
          setDisplayedText(targetText);
          isDecoding.current = false;
        }
      }, interval);
    }, delay);
  };

  return { displayedText, startDecoding };
};
