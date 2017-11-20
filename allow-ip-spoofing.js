/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2017, Brian Bennett.
 */

/*
 * Enables allow_ip_spoofing for all created instances on
 * specified users on specified networks.
 *
 * The purpose of this plugin is to allow slaac/addrconf IPv6
 * interface configuration until Triton supports IPv6 networks
 * proper. Obviously, this is a security risk and should only be
 * used in strictly trusted circumstances.
 */

module.exports = {

    var allowed_users = [
        ""
    ];
    var allowed_networks = [
        ""
    ];

    /**
    * Creates a pre-provisioning hook.
    *
    * Config is the JS object that was converted from the
    * free-form config object that is defined in config.json.
    *
    * This function must return a restify filter that is run as part
    * of a restify "pre" chain.
    *
    * @param {Object} config free-form config from config.json.
    * @return {Function} restify 'pre' filter.
    */
    /*******
    preProvision: function(config) {

        return function(req, res, next) {
            return next();
        };
    };
    *******/

    /**
    * Creates a post-provisioning hook.
    *
    * Config is the JS object that was converted from the
    * free-form config object that is defined in config.json.
    *
    * This function must return a restify filter that is run as part
    * of a restify "post" chain.
    *
    * @param {Object} config free-form config from config.json.
    * @return {Function} restify 'post' filter.
    */
    postProvision: function(config) {

        return function(req, res, next) {
            var m = res.machine;
            var nics = m.nics;
            if (allowed_users.indexOf(m.owner_uuid) === -1) {
                return next();
            };
            nics.foreach(n) {
                var params = {
                    uuid: m.uuid
                };
                if (allowed_networks.indexOf(n.network_uuid) > -1) {
                    params.nics.push({
                        mac: n.mac,
                        allow_ip_spoofing: true
                    }
                };
            };

            if (params.nics.length > 0) {
                req.vmapi.updateVm(params, next);
                return 0;
            } else {
                return next();
            };
        };
    };
};

