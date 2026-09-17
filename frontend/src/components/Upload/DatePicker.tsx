import React from 'react';

import LuxonUtils from '@date-io/luxon';
import { MuiPickersUtilsProvider, KeyboardDatePicker } from '@material-ui/pickers';
import { MaterialUiPickersDate } from '@material-ui/pickers/typings/date';

export interface DateChangeEvent {
    name: string;
    value: Date;
}

interface DatePickerProps {
    name: string;
    label: string;
    value: Date | null;
    error: string | null;
    required?: boolean;
    autoComplete: string;
    autoFocus?: boolean;
    onChange: (event: DateChangeEvent) => void;
}

const DatePicker: React.FC<DatePickerProps> = ({
    name,
    label,
    value,
    error,
    required = false,
    autoComplete,
    autoFocus = false,
    onChange,
}: DatePickerProps) => {
    const handleDateChange = (date: MaterialUiPickersDate): void => {
        if (date) onChange({ name, value: date.toJSDate() });
    };

    return (
        <MuiPickersUtilsProvider utils={LuxonUtils}>
            <KeyboardDatePicker
                name={name}
                variant="inline"
                inputVariant="outlined"
                fullWidth
                margin="normal"
                openTo="year"
                views={['year', 'month', 'date']}
                format="dd. MM. yyyy"
                autoOk
                label={label}
                required={required}
                disableToolbar
                autoComplete={autoComplete}
                autoFocus={autoFocus}
                value={value}
                onChange={handleDateChange}
                KeyboardButtonProps={{
                    'aria-label': 'change date',
                }}
                error={error !== null}
                helperText={error || ''}
            />
        </MuiPickersUtilsProvider>
    );
};

export default DatePicker;
