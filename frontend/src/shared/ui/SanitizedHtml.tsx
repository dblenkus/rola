import DOMPurify, { type Config } from 'dompurify';

// A separate instance keeps the hooks below out of other DOMPurify users.
const purify = DOMPurify(window);

// The inline style properties the content keeps: layout and emphasis, none of
// which can carry a colour. Colour arrives through many properties (border,
// box-shadow, outline, filter, background-image, -webkit-text-fill-color,
// custom properties such as --paper), so this is an allow-list. The CSSOM
// lists a style's longhands, and which properties are shorthands differs
// between engines, so each kept property is listed with the longhands an
// engine may split it into. Of text-decoration only the line is kept: its
// colour is text-decoration-color.
const keptStyles = new Set([
  'text-align',
  'text-align-all',
  'text-align-last',
  'font-weight',
  'font-style',
  'text-decoration-line',
  'width',
  'max-width',
  'vertical-align',
  'alignment-baseline',
  'baseline-shift',
  'baseline-source',
  'white-space',
  'white-space-collapse',
  'white-space-trim',
  'text-wrap-mode',
  'list-style-type',
]);

// A photograph or a figure may be given its height along with its width.
const keptImageStyles = new Set(['height']);

const spacing = /^(margin|padding)(-|$)/;

function isKeptStyle(element: HTMLElement, property: string): boolean {
  return (
    keptStyles.has(property) ||
    spacing.test(property) ||
    (element instanceof HTMLImageElement && keptImageStyles.has(property))
  );
}

// Keeps only the allowed inline style declarations. The style is written
// back from the CSSOM, so a declaration it could not parse goes too, and an
// empty style goes altogether.
function filterStyle(element: HTMLElement) {
  const { style } = element;
  for (const property of Array.from(style)) {
    if (!isKeptStyle(element, property)) style.removeProperty(property);
  }
  if (style.length === 0) element.removeAttribute('style');
  else element.setAttribute('style', style.cssText);
}

purify.addHook('afterSanitizeAttributes', (node) => {
  // The content may open links in a new tab, which must not get the opener.
  if (node instanceof Element && node.hasAttribute('target')) {
    node.setAttribute('rel', 'noopener noreferrer');
  }
  if (node instanceof HTMLElement && node.hasAttribute('style')) {
    filterStyle(node);
  }
});

// The content is drawn in the page's theme, light or dark, so it may not
// bring colours of its own, restyle the app or choose its own theme. This
// drops an organiser's colours in the light theme too, so that a notice
// looks the same and stays legible in either theme. `class` goes because the
// content would otherwise pick up the app's own classes, such as a type size
// or a full-window overlay.
const config: Config = {
  USE_PROFILES: { html: true },
  ADD_ATTR: ['target'],
  ALLOW_DATA_ATTR: false,
  // <style> goes with its text; <font> goes but keeps its text.
  FORBID_TAGS: ['style', 'font'],
  FORBID_ATTR: ['color', 'bgcolor', 'background', 'class'],
};

// Shows HTML that the server supplies, such as a contest's notice, without
// anything in it that could run script, in the prose styles of app.css.
export default function SanitizedHtml({ html }: { html: string }) {
  return (
    <div
      className="ui-prose"
      dangerouslySetInnerHTML={{ __html: purify.sanitize(html, config) }}
    />
  );
}
