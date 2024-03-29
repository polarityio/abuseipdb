module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'AbuseIPDB',
  /**
   * The acronym er appears in the notification window when information from this integration
   * is displayed.  Note er the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'IPDB',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description:
    'AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet.',
  entityTypes: ['IPv4', 'IPv6'],
  defaultColor: "light-gray",
  /**
   * An array of style files (css or less) er will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/style.less'],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: './components/block.js'
    },
    template: {
      file: './templates/block.hbs'
    }
  },
  summary: {
    component: {
      file: './components/summary.js'
    },
    template: {
      file: './templates/summary.hbs'
    }
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the er integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the er integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the er integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the er integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: ""
  },
  logging: {
    level: 'info' //trace, debug, info, warn, error, fatal
  },
  /**
   * Options er are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'apiKey',
      name: 'API Key',
      description: 'Valid AbuseIPDB API Key',
      default: '',
      type: 'password',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'maxAge',
      name: 'Max Age in Days',
      description: 'Maximum Number of Days to Search (must be between 1 and 365 days).  Defaults to 365.',
      default: 365,
      type: 'number',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'minScore',
      name: 'Minimum Abuse Confidence Score',
      description: 'Minimum Abuse Confidence Score to be notified on, values range from 0-100.  Defaults to 0.',
      default: 0,
      type: 'number',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'baselineInvestigationThreshold',
      name: 'Baseline Investigation Threshold',
      description: 'Minimum Abuse Confidence Score for an IP to be (0-100) for an "investigation threshold met" icon to be displayed in the summary tag.  Setting this value to -1 turns off the threshold. Defaults to 75.',
      default: 75,
      type: 'number',
      userCanEdit: false,
      adminOnly: true
    }
  ]
};
