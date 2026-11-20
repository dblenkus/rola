import './Footer.css';

// The page's contentinfo: the year and the author, under a hairline at the
// bottom of the page, also on a short one.
export default function Footer() {
  return (
    <footer className="ui-footer small">
      {new Date().getFullYear()} - Domen Blenkuš
    </footer>
  );
}
