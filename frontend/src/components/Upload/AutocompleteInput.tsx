import React, { ReactNode } from 'react';

import Autocomplete from '@material-ui/lab/Autocomplete';
import { CircularProgress, TextField } from '@material-ui/core';

import { InputChange } from '../../types/models';
import { Institution } from '../../types/api';
import InstitutionService from '../../services/InstitutionService';

export interface AutocompleteFieldProps {
    name: string;
    label: string;
    value: string;
    error: string | null;
    required: boolean;
    autoFocus?: boolean;
    onChange: (event: InputChange) => void;
}

const AutocompleteField: React.FC<AutocompleteFieldProps> = ({
    name,
    label,
    value,
    required,
    error,
    autoFocus,
    onChange,
}: AutocompleteFieldProps) => {
    const [open, setOpen] = React.useState(false);
    const [options, setOptions] = React.useState<Institution[]>([]);
    const loading = open && options.length === 0;

    const handleChange = (event: React.ChangeEvent<{}>, institution: Institution | null): void => {
        console.log('>', institution, { name, value: institution ? institution.name : '' });
        onChange({ name, value: institution ? institution.name : '' });
    };

    React.useEffect(() => {
        let active = true;

        if (!loading) return undefined;

        const fetchInstitutions = async (): Promise<void> => {
            const { data } = await InstitutionService.getInstitutions();
            if (active) setOptions(data.results);
        };

        fetchInstitutions();

        return (): void => {
            active = false;
        };
    }, [loading]);

    React.useEffect(() => {
        if (!open) {
            setOptions([]);
        }
    }, [open]);

    return (
        <Autocomplete<Institution>
            value={options.find((institution) => institution.name === value)}
            open={open}
            onOpen={(): void => {
                setOpen(true);
            }}
            onClose={(): void => {
                setOpen(false);
            }}
            getOptionSelected={(option, selected): boolean => option.name === selected.name}
            getOptionLabel={(option): string => option.name}
            options={options}
            loading={loading}
            onChange={handleChange}
            renderInput={(params): ReactNode => (
                <TextField
                    {...params}
                    name={name}
                    variant="outlined"
                    margin="normal"
                    fullWidth
                    label={label}
                    required={required}
                    autoFocus={autoFocus}
                    error={error !== null}
                    helperText={error || ''}
                    InputProps={{
                        ...params.InputProps,
                        endAdornment: (
                            <>
                                {loading && <CircularProgress color="inherit" size={20} />}
                                {params.InputProps.endAdornment}
                            </>
                        ),
                    }}
                />
            )}
        />
    );
};

export default AutocompleteField;
