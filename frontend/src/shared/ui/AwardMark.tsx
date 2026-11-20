import Icon from './Icon';

interface AwardMarkProps {
  // The award's name exactly as the organiser entered it.
  name: string;
  // The ribbon alone, for a thumbnail's ID caption; the name stays for
  // screen readers.
  compact?: boolean;
}

// Marks an awarded photo with the award ribbon and the award's name, in
// ink, beside or under the photo and never on it.
export default function AwardMark({ name, compact }: AwardMarkProps) {
  return (
    <span className={compact ? 'rl-award rl-award--compact' : 'rl-award label'}>
      <Icon name="award" size={compact ? 14 : 16} className="rl-award__icon" />
      <span className="rl-award__name">{name}</span>
    </span>
  );
}
