'use strict';

const request = require('request');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

let Logger;
let requestDefault;

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
      //do the lookup
      let requestOptions = {
        method: 'GET',
        uri: 'https://api.abuseipdb.com/api/v2/check',
        body: {
          maxAgeInDays: options.maxAge
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

      tasks.push(function(done) {
        requestDefault(requestOptions, function(error, res, body) {
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
              body: body
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
      if (result.body === null || _isMiss(result.body) || result.body.data.abuseConfidenceScore <= options.minScore) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: _generateTags(result.body.data),
            details: result.body
          }
        });
      }
    });

    Logger.trace({ lookupResults: lookupResults }, 'Lookup Results');

    cb(null, lookupResults);
  });
}

function _generateTags(result) {
  let tags = [];

  if (result.isWhitelisted === true) {
    tags.push('Is Whitelisted');
  }
  if (typeof result.abuseConfidenceScore !== 'undefined') {
    tags.push(`Abuse Confidence Score: ${result.abuseConfidenceScore}`);
  }
  if (typeof result.domain !== 'undefined') {
    tags.push(`Associated Domain: ${result.domain}`);
  }
  if (typeof result.totalReports !== 'undefined' && typeof result.numDistinctUsers !== 'undefined') {
    tags.push(`${result.totalReports} reports from ${result.numDistinctUsers} distinct users`);
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
