'use strict';

const request = require('postman-request');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

let Logger;
let requestDefault;

const MAX_CATEGORY_SUMMARY_TAGS = 3;

// Categories are returned by the API as Integer IDs.  We map those IDs to human readable strings here
// This information comes from: https://www.abuseipdb.com/categories
const CATEGORIES = {
  1: 'DNS Compromise',
  2: 'DNS Poisoning',
  3: 'Fraud Orders',
  4: 'DDoS Attack',
  5: 'FTP Brute-Force',
  6: 'Ping of Death',
  7: 'Phishing',
  8: 'Fraud VOIP',
  9: 'Open Proxy',
  10: 'Web Spam',
  11: 'Email Spam',
  12: 'Blog Spam',
  13: 'VPN IP',
  14: 'Port Scan',
  15: 'Hacking',
  16: 'SQL Injection',
  17: 'Spoofing',
  18: 'Brute Force',
  19: 'Bad Web Bot',
  20: 'Exploited Host',
  21: 'Web App Attack',
  22: 'SSH',
  23: 'IoT Targeted'
};

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  Logger.trace({ entities: entities }, 'entities');

  entities.forEach((entity) => {
    if (entity.value) {
      const requestOptions = {
        method: 'GET',
        uri: 'https://api.abuseipdb.com/api/v2/check',
        body: {
          maxAgeInDays: options.maxAge,
          verbose: true
        },
        headers: {
          Key: options.apiKey
        },
        qs: {
          ipAddress: entity.value
        },
        json: true
      };

      Logger.debug({ uri: requestOptions }, 'Request URI');

      tasks.push(function (done) {
        requestDefault(requestOptions, function (error, res, body) {
          if (error) {
            done({
              error: error,
              entity: entity.value,
              detail: 'Error in Request'
            });
            return;
          }

          let result = {};
          if (res.statusCode === 200) {
            result = {
              entity: entity,
              body: body,
              headers: res.headers
            };
          } else if (res.statusCode === 429) {
            // reached rate limit
            error = { detail: 'Reached API Lookup Limit' };
          } else if (res.statusCode === 422) {
            // days exceeded bounds
            error = { detail: 'The max age in days must be between 1 and 365.' };
          } else {
            // Non 200 status code
            done({
              error: error,
              httpStatus: res.statusCode,
              body: body,
              detail: 'Unexpected Non 200 HTTP Status Code',
              entity: entity.value
            });
            return;
          }

          done(error, result);
        });
      });
    }
  });

  async.parallelLimit(tasks, 10, (err, results) => {
    if (err) {
      cb(err);
      return;
    }

    results.forEach((result) => {
      if (result.body === null || _isMiss(result.body) || result.body.data.abuseConfidenceScore < options.minScore) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        const categories = _getUniqueCategories(result.body.data);
        const summary = _generateTags(result.body.data, categories, options);
        const data = result.body.data;
        // the reports property is used to generate the categories but is not needed in the overlay window
        // Given how large it is we remove it before sending back the data.
        delete data.reports;

        lookupResults.push({
          entity: result.entity,
          data: {
            summary,
            details: {
              data,
              categories,
              quota: {
                remaining: result.headers['x-ratelimit-remaining'],
                limit: result.headers['x-ratelimit-limit'],
                reset: result.headers['x-ratelimit-reset']
              }
            }
          }
        });
      }
    });

    Logger.trace({ lookupResults: lookupResults }, 'Lookup Results');

    cb(null, lookupResults);
  });
}

/**
 * Returns an array of category objects where each category object is made up of the name
 * of the category and the count (i.e., how many reports that category appeared in).  We then
 * sort the array by count so that the highest count category is in position index 0.
 *
 * Example return payload:
 * ```
 * [
 *   {
 *    name: 'Category Name',
 *    count: 34
 *   },
 *   {
 *     name: 'Category Name 2',
 *     count: 24
 *   }
 * ]
 * ```
 *
 * @param result
 * @returns {*[]}
 * @private
 */
function _getUniqueCategories(result) {
  const categoryIds = new Map();
  const categories = [];

  // Compute counts for all categories and store in categoryIds
  if (Array.isArray(result.reports)) {
    for (let i = 0; i < result.reports.length; i++) {
      const report = result.reports[i];
      for (let j = 0; j < report.categories.length; j++) {
        const category = report.categories[j];
        // There appear to be some categories with an ID of 0 but these categories are not documented on the AbuseIPDB
        // website here: https://www.abuseipdb.com/categories
        // As a result, we just ignore them
        if (category !== 0) {
          categoryIds.set(category, categoryIds.get(category) + 1 || 1);
        }
      }
    }
  }

  // Convert from category IDs to human readable names
  for (let key of categoryIds.keys()) {
    categories.push({
      name: CATEGORIES[key],
      count: categoryIds.get(key)
    });
  }

  // sort categories by value (i.e., the count) so the highest count categories come first
  let sortedCategories = categories.sort((a, b) => b.count - a.count);

  return sortedCategories;
}

function _generateTags(result, categories, options) {
  let tags = [];

  if (typeof result.abuseConfidenceScore !== 'undefined') {
    if (result.abuseConfidenceScore > options.baselineInvestigationThreshold && options.baselineInvestigationThreshold !== -1) {
      tags.push({
        type: 'danger',
        text: `Confidence of Abuse: ${result.abuseConfidenceScore}%`
      });
    } else {
      tags.push(`Confidence of Abuse: ${result.abuseConfidenceScore}%`);
    }
  }
  if (result.isWhitelisted === true) {
    tags.push('Is Allowlisted');
  }
  if (typeof result.domain !== 'undefined') {
    tags.push(`Associated Domain: ${result.domain}`);
  }
  if (typeof result.totalReports !== 'undefined' && typeof result.numDistinctUsers !== 'undefined') {
    if(result.totalReports > 0){
      tags.push(`${result.totalReports} reports from ${result.numDistinctUsers} distinct users`);
    } else {
      tags.push('No reports');
    }
  }

  for (let i = 0; i < categories.length && i < MAX_CATEGORY_SUMMARY_TAGS; i++) {
    tags.push(categories[i].name);
  }

  if (categories.length > MAX_CATEGORY_SUMMARY_TAGS) {
    tags.push(`+${categories.length - MAX_CATEGORY_SUMMARY_TAGS} more categories`);
  }
  return tags;
}

function _isMiss(body) {
  if (body && Array.isArray(body) && body.length === 0) {
    return true;
  }

  if (!body.data) {
    return true;
  }

  return false;
}

function startup(logger) {
  Logger = logger;

  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  requestDefault = request.defaults(defaults);
}

function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.apiKey.value !== 'string' ||
    (typeof userOptions.apiKey.value === 'string' && userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a valid AbuseIPDB API key'
    });
  }

  if (userOptions.minScore.value < 0 || userOptions.minScore.value > 100) {
    errors.push({
      key: 'minScore',
      message: 'The Minimum Abuse Confidence Score must be between 0 and 100'
    });
  }

  if (userOptions.baselineInvestigationThreshold.value < -1 || userOptions.baselineInvestigationThreshold.value > 100) {
    errors.push({
      key: 'baselineInvestigationThreshold',
      message: 'The Baseline Investigation Threshold must be between 0 and 100'
    });
  }

  if (userOptions.maxAge.value < 1 || userOptions.maxAge.value > 365) {
    errors.push({
      key: 'maxAge',
      message: 'The Max Age in Days must be between 1 and 365'
    });
  }

  cb(null, errors);
}

module.exports = {
  doLookup: doLookup,
  validateOptions: validateOptions,
  startup: startup
};
