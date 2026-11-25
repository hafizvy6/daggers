/* Daggers · inline SVG icons + logo mark. No external requests, ever. */

const S = (body, { size = 18, vb = "0 0 24 24", cls = "" } = {}) =>
  `<svg class="${cls}" width="${size}" height="${size}" viewBox="${vb}" fill="none" aria-hidden="true" focusable="false">${body}</svg>`;

const stroke = 'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';

export const icons = {
  radar: (o) => S(`<circle cx="12" cy="12" r="9" ${stroke}/><circle cx="12" cy="12" r="4.5" ${stroke}/><path d="M12 12l6.4-6.4" ${stroke}/><circle cx="12" cy="12" r="1.4" fill="currentColor"/>`, o),
  sweep: (o) => S(`<rect x="3.5" y="4.5" width="17" height="6" rx="1.5" ${stroke}/><rect x="3.5" y="13.5" width="17" height="6" rx="1.5" ${stroke}/><circle cx="7.5" cy="7.5" r="1.2" fill="currentColor"/><path d="M10.5 7.5h7M7.5 16.5h10" ${stroke}/>`, o),
  check: (o) => S(`<path d="M4 12.5l5 5L20 6.5" ${stroke}/>`, o),
  shield: (o) => S(`<path d="M12 3l7 2.6v5.2c0 4.4-2.9 7.6-7 9.2-4.1-1.6-7-4.8-7-9.2V5.6L12 3z" ${stroke}/>`, o),
  phone: (o) => S(`<path d="M7 3.8h10a1.6 1.6 0 011.6 1.6v13.2A1.6 1.6 0 0117 20.2H7a1.6 1.6 0 01-1.6-1.6V5.4A1.6 1.6 0 017 3.8z" ${stroke}/><path d="M10.5 17.4h3" ${stroke}/>`, o),
  portal: (o) => S(`<rect x="3.5" y="4" width="17" height="16" rx="1.6" ${stroke}/><path d="M3.5 9h17M9.5 9v11" ${stroke}/>`, o),
  finger: (o) => S(`<path d="M8 12V8a4 4 0 018 0v4M5 12v-2a7 7 0 0114 0v2M12 12v5M9 20a7 7 0 01-1.5-2M15 20a7 7 0 001.8-3.4" ${stroke}/>`, o),
  copy: (o) => S(`<rect x="8.5" y="8.5" width="12" height="12" rx="1.6" ${stroke}/><path d="M15.5 8.5v-3A1.5 1.5 0 0014 4H4.5A1.5 1.5 0 003 5.5V15a1.5 1.5 0 001.5 1.5h4" ${stroke}/>`, o),
  arrow: (o) => S(`<path d="M5 12h14M13 6l6 6-6 6" ${stroke}/>`, o),  // mirrored in RTL via CSS
  back: (o) => S(`<path d="M19 12H5M11 6l-6 6 6 6" ${stroke}/>`, o),
  menu: (o) => S(`<path d="M4 6.5h16M4 12h16M4 17.5h16" ${stroke}/>`, o),
  bolt: (o) => S(`<path d="M13 2.5L4.5 13.5H11L9.5 21.5 19.5 10H13l0-7.5z" ${stroke}/>`, o),
  doc: (o) => S(`<path d="M6 3.5h8l4.5 4.5V20a.5.5 0 01-.5.5H6a.5.5 0 01-.5-.5V4a.5.5 0 01.5-.5z" ${stroke}/><path d="M14 3.5V8h4.5M9 12h6M9 15.5h6" ${stroke}/>`, o),
  spark: (o) => S(`<path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M18.4 5.6l-2.8 2.8M8.4 15.6l-2.8 2.8" ${stroke}/>`, o),
  globe: (o) => S(`<circle cx="12" cy="12" r="9" ${stroke}/><path d="M3 12h18M12 3c2.6 2.5 3.9 5.6 3.9 9s-1.3 6.5-3.9 9c-2.6-2.5-3.9-5.6-3.9-9S9.4 5.5 12 3z" ${stroke}/>`, o),
  pin: (o) => S(`<path d="M12 21s-7-5.4-7-11a7 7 0 1114 0c0 5.6-7 11-7 11z" ${stroke}/><circle cx="12" cy="10" r="2.6" ${stroke}/>`, o),
  wifiOff: (o) => S(`<path d="M3 3l18 18M8.6 15.4a5 5 0 016.8 0M5.2 12a10.5 10.5 0 013.2-2M15 9.4a10.5 10.5 0 013.8 2.6M2 8.6A15 15 0 016.4 6M17.6 6a15 15 0 014.4 2.6M12 19h.01" ${stroke}/>`, o),
  down: (o) => S(`<path d="M12 3v13M6.5 10.5L12 16l5.5-5.5M4 20.5h16" ${stroke}/>`, o),
  external: (o) => S(`<path d="M14 4h6v6M20 4l-9 9M18 14v5.5A1.5 1.5 0 0116.5 21h-12A1.5 1.5 0 013 19.5v-12A1.5 1.5 0 014.5 6H10" ${stroke}/>`, o),
  play: (o) => S(`<path d="M7 4.5l12 7.5-12 7.5v-15z" ${stroke}/>`, o),
  stop: (o) => S(`<rect x="6" y="6" width="12" height="12" rx="1.4" ${stroke}/>`, o),
};

/** The Daggers brand mark. */
export const logoMark = ({ size = 28 } = {}) =>
  `<img src="./icons/logo.png" width="${size}" height="${size}" alt="" aria-hidden="true" style="display:block;flex:none;object-fit:contain" />`;

/** Friendly shield mascot for empty states. */
export const mascot = ({ size = 72, mood = "calm" } = {}) => `
<svg width="${size}" height="${size}" viewBox="0 0 96 96" fill="none" aria-hidden="true">
  <path d="M48 8l30 11v21c0 17.6-11.7 30.7-30 37.2C29.7 70.7 18 57.6 18 40V19L48 8z"
        fill="var(--surface)" stroke="var(--ink)" stroke-width="3" stroke-linejoin="round"/>
  <circle cx="38" cy="44" r="3.4" fill="var(--ink)"/>
  <circle cx="58" cy="44" r="3.4" fill="var(--ink)"/>
  ${mood === "calm"
    ? '<path d="M38 57c3 3.4 7 5 10 5s7-1.6 10-5" stroke="var(--ink)" stroke-width="3" stroke-linecap="round"/>'
    : '<path d="M39 59c3-2.4 6-3.4 9-3.4s6 1 9 3.4" stroke="var(--ink)" stroke-width="3" stroke-linecap="round"/>'}
  <path d="M48 24l6 9h-12l6-9z" fill="var(--accent)"/>
</svg>`;
export const logo = logoMark;
