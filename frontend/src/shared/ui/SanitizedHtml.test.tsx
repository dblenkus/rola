import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import SanitizedHtml from './SanitizedHtml';

it('keeps formatting and removes executable markup', () => {
  const { container } = render(
    <SanitizedHtml
      html={
        '<strong>Instructions</strong><script>alert(1)</script><img src="x" onerror="alert(2)">'
      }
    />,
  );
  expect(screen.getByText('Instructions').tagName).toBe('STRONG');
  expect(container.querySelector('script')).toBeNull();
  expect(container.querySelector('img')).not.toHaveAttribute('onerror');
});

it('opens links in a new tab without giving them the opener', () => {
  render(
    <SanitizedHtml
      html={
        '<a href="https://example.com/rules.pdf" target="_blank" rel="opener">Rules</a> <a href="https://example.com/">Home</a>'
      }
    />,
  );
  const rules = screen.getByRole('link', { name: 'Rules' });
  expect(rules).toHaveAttribute('target', '_blank');
  expect(rules).toHaveAttribute('rel', 'noopener noreferrer');
  expect(screen.getByRole('link', { name: 'Home' })).not.toHaveAttribute('rel');
});

// The content is drawn in the page's theme, so it may bring no colours,
// styles or theme of its own.
function sanitized(html: string): HTMLElement {
  const { container } = render(<SanitizedHtml html={html} />);
  const prose = container.firstElementChild;
  if (!(prose instanceof HTMLElement)) throw new Error('nothing rendered');
  return prose;
}

function only(prose: HTMLElement, selector: string): HTMLElement {
  const element = prose.querySelector(selector);
  if (!(element instanceof HTMLElement)) {
    throw new Error(`no ${selector} in the content`);
  }
  return element;
}

it('keeps ordinary rich text unchanged', () => {
  const html =
    '<h2>Rules</h2><p>Send <strong>three</strong> <em>original</em> photographs, ' +
    'see <a href="https://example.com/rules">the rules</a>.</p>' +
    '<ul><li>One</li><li>Two</li></ul><ol><li>First</li></ol>' +
    '<table><tbody><tr><th>Category</th><td>Nature</td></tr></tbody></table>' +
    '<p><img src="https://example.com/logo.png" alt="Logo"></p>';
  expect(sanitized(html).innerHTML).toBe(html);
});

it.each([
  'text-align: center;',
  'font-weight: bold;',
  'font-style: italic;',
  'text-decoration-line: underline;',
  'width: 50%;',
  'max-width: 100%;',
  'margin: 0px auto;',
  'margin-top: 8px;',
  'padding: 4px;',
  'padding-left: 1em;',
  'vertical-align: middle;',
  'white-space: nowrap;',
  'list-style-type: square;',
])('keeps the inline style %s', (declaration) => {
  const prose = sanitized(`<p style="${declaration}">Text</p>`);
  expect(only(prose, 'p')).toHaveAttribute('style', declaration);
});

it('keeps the height of an image but not of other elements', () => {
  const prose = sanitized(
    '<img src="https://example.com/a.png" alt="A" style="height: 40px;">' +
      '<p style="height: 40px;">Text</p>',
  );
  expect(only(prose, 'img')).toHaveAttribute('style', 'height: 40px;');
  expect(only(prose, 'p')).not.toHaveAttribute('style');
});

it.each([
  'color: #000000',
  'background: #ffffff',
  'background-color: yellow',
  'background-image: url(https://example.com/a.png)',
  'border: 1px solid red',
  'box-shadow: 0 0 4px red',
  'outline: 2px solid red',
  '-webkit-text-fill-color: red',
  'filter: invert(1)',
  'font-size: 40px',
  'position: fixed',
  '--paper: #000000',
])('removes the inline style %s and the attribute with it', (declaration) => {
  const prose = sanitized(`<p style="${declaration}">Text</p>`);
  expect(only(prose, 'p')).not.toHaveAttribute('style');
  expect(prose).toHaveTextContent('Text');
});

it('keeps only the allowed parts of a mixed inline style', () => {
  const prose = sanitized(
    '<p style="color: #000; text-align: center; --paper: #000; ' +
      'background: #fff; font-weight: bold">Text</p>',
  );
  expect(only(prose, 'p')).toHaveAttribute(
    'style',
    'text-align: center; font-weight: bold;',
  );
});

it('keeps the line of a text decoration but not its colour', () => {
  const prose = sanitized('<p style="text-decoration: underline red">Text</p>');
  expect(only(prose, 'p')).toHaveAttribute(
    'style',
    'text-decoration-line: underline;',
  );
});

it('removes style elements with their text', () => {
  // A leading <style> would be parsed into the head and dropped anyway.
  const prose = sanitized(
    '<p>Notice</p><style>body { background: red }</style><p>End</p>',
  );
  expect(prose.querySelector('style')).toBeNull();
  expect(prose.innerHTML).toBe('<p>Notice</p><p>End</p>');
});

it('removes data attributes, so the content cannot choose its theme', () => {
  const prose = sanitized('<div data-theme="dark" data-x="1">Notice</div>');
  const div = only(prose, 'div');
  expect(div).not.toHaveAttribute('data-theme');
  expect(div).not.toHaveAttribute('data-x');
});

it.each(['rl-on-viewing', 'display small caption', 'ui-dialog-overlay'])(
  'removes the class %s, so the content cannot use the app classes',
  (name) => {
    const prose = sanitized(`<p class="${name}">Notice</p>`);
    expect(only(prose, 'p')).not.toHaveAttribute('class');
    expect(prose).toHaveTextContent('Notice');
  },
);

it('removes colour attributes', () => {
  const prose = sanitized(
    '<table bgcolor="#000" background="https://example.com/a.png">' +
      '<tbody><tr><td bgcolor="red">Cell</td></tr></tbody></table>' +
      '<hr color="red">',
  );
  for (const element of prose.querySelectorAll('*')) {
    expect(element).not.toHaveAttribute('bgcolor');
    expect(element).not.toHaveAttribute('background');
    expect(element).not.toHaveAttribute('color');
  }
  expect(prose).toHaveTextContent('Cell');
});

it('removes font elements but keeps their text', () => {
  const prose = sanitized(
    '<p><font color="#000" face="Comic Sans MS" size="7">Dark</font> text</p>',
  );
  expect(prose.querySelector('font')).toBeNull();
  expect(only(prose, 'p').innerHTML).toBe('Dark text');
});

it('removes SVG and MathML', () => {
  const prose = sanitized(
    '<p>Before</p><svg><rect fill="black" width="10" height="10"></rect></svg>' +
      '<math><mi>x</mi></math><p>After</p>',
  );
  expect(prose.querySelector('svg, rect, math, mi')).toBeNull();
  expect(prose.innerHTML).toBe('<p>Before</p><p>After</p>');
});
