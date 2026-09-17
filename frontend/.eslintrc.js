module.exports = {
    env: {
        browser: true,
        jest: true,
    },
    extends: [
        'plugin:@typescript-eslint/recommended',
        'plugin:@typescript-eslint/recommended-requiring-type-checking',
        'airbnb',
        'airbnb/hooks',
        'prettier/react',
        // Uses eslint-config-prettier to disable ESLint rules from
        // @typescript-eslint/eslint-plugin that would conflict with
        // prettier.
        'prettier/@typescript-eslint',
        // Enables eslint-plugin-prettier and eslint-config-prettier.
        // This will display prettier errors as ESLint errors. Make sure
        // this is always the last configuration in the extends array.
        'plugin:prettier/recommended',
    ],
    parser: '@typescript-eslint/parser',
    parserOptions: {
        ecmaFeatures: {
            jsx: true,
        },
        ecmaVersion: 2018,
        sourceType: 'module',
        project: './tsconfig.json',
        tsconfigRootDir: __dirname,
    },
    rules: {
        // .tsx files can include JSX.
        'react/jsx-filename-extension': ['warn', { extensions: ['.tsx'] }],
        // Ensure consistent use of file extension within import path.
        'import/extensions': ['error', 'never', { svg: 'always' }],
    },
    settings: {
        'import/resolver': {
            node: {
                extensions: ['.js', '.jsx', '.ts', '.tsx', '.svg'],
                moduleDirectory: ['node_modules', 'src'],
            },
        },
    },
};
