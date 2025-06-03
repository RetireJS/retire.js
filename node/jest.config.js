// eslint-disable-next-line no-undef
module.exports = {
  transform: {
    '^.+\\.ts?$': [
      'ts-jest'
    ],
  },
  testEnvironment: 'node',
  testRegex: '/tests/.*\\.(test|spec)?\\.(ts|tsx)$',
  moduleFileExtensions: ['ts', 'js' ],
};