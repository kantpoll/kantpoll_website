/**
 * Kantpoll Project
 * https://github.com/kantpoll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

importScripts("../urs/urs.min.js");

/**
 * It signs a vote
 * @param {Event} event
 */
onmessage = function (event) {
    let arguments_json = JSON.parse(event.data);

    //Arguments of "roda": verify-text, sign-text, keyring, keypair, signature, blind
    let signature = urs.roda("", arguments_json.vote_message, arguments_json.pubkeys, arguments_json.keypair, "", false);

    postMessage(signature)
};