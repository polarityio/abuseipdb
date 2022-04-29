'use strict';
polarity.export = PolarityComponent.extend({
  data: Ember.computed.alias('block.data.details.data'),
  quota: Ember.computed.alias('block.data.details.quota'),
  categories: Ember.computed.alias('block.data.details.categories'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  })
});
