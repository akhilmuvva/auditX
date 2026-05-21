import { useEffect, useRef } from 'react';
import anime, { AnimeParams, AnimeInstance } from 'animejs';

export const useAnime = (
  params: AnimeParams,
  dependencies: any[] = [],
  playOnMount = true
) => {
  const animeRef = useRef<AnimeInstance | null>(null);

  useEffect(() => {
    // Merge autoplay configuration safely
    const animationParams = {
      ...params,
      autoplay: playOnMount,
    };

    animeRef.current = anime(animationParams);

    return () => {
      if (animeRef.current) {
        anime.remove(params.targets as any);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, dependencies);

  return {
    play: () => animeRef.current?.play(),
    pause: () => animeRef.current?.pause(),
    restart: () => animeRef.current?.restart(),
  };
};
