import { useTranslation } from 'react-i18next';
import {
  daysLeft,
  formatDate,
  parseApiDate,
  type DateLanguage,
} from '../../../shared/utils/formatDate';

export interface Deadline {
  // "Entries close", or "Entries closed" once the moment has passed.
  label: string;
  // The closing day, written as Rola writes dates.
  date: string;
  // "22 days left" or "last day" while entries are open; null after.
  remaining: string | null;
}

// The wording of a contest's closing date (its `end_date`) at render time.
export default function useDeadline(endDate: string): Deadline {
  const { t, i18n } = useTranslation();
  // The supported languages are 'sl' and 'en', which is also the fallback.
  const language: DateLanguage = i18n.resolvedLanguage === 'sl' ? 'sl' : 'en';
  const end = parseApiDate(endDate);
  const now = new Date();
  const date = formatDate(end, language);
  if (end.getTime() < now.getTime()) {
    return { label: t('contests_entries_closed'), date, remaining: null };
  }
  const days = daysLeft(end, now);
  return {
    label: t('contests_entries_close'),
    date,
    remaining:
      days === 0 ? t('date_last_day') : t('date_days_left', { count: days }),
  };
}
