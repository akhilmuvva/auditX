import { useEffect, useRef } from 'react';
import { animate, type JSAnimation } from 'animejs';

type AnimateParams = Parameters<typeof animate>[1];

export const useAnime = (
  params: AnimateParams & { targets: string | Element | Element[] | NodeList },
  dependencies: unknown[] = [],
  playOnMount = true
) => {
  const animeRef = useRef<JSAnimation | null>(null);

  useEffect(() => {
    try {
      const { targets, ...rest } = params;

      // Bail out if a string selector resolves to nothing
      if (typeof targets === 'string') {
        const els = document.querySelectorAll(targets);
        if (els.length === 0) return;
      }

      animeRef.current = animate(targets as any, {
        ...rest,
        autoplay: playOnMount,
      });
    } catch (e) {
      // Silently swallow animation errors (e.g. missing DOM nodes on first render)
    }

    return () => {
      try { animeRef.current?.cancel(); } catch {}
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, dependencies);

  return {
    play: () => { try { animeRef.current?.play(); } catch {} },
    pause: () => { try { animeRef.current?.pause(); } catch {} },
    restart: () => { try { animeRef.current?.restart(); } catch {} },
  };
};
