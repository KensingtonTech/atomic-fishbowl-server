import { Preferences } from './types/preferences';

export const DefaultAfbPreferences: Omit<Preferences, 'serviceTypes' | 'nw' | 'sa'> = {
  minX: 255,
  minY: 255,  
  defaultContentLimit: 1000,
  defaultRollingHours: 1,
  debugLogging: false,
  // serviceTypes is inserted dynamically, and is not saved into the database.  This allows us to hard-code the service type at build-time
  tokenExpirationHours: 24
};
