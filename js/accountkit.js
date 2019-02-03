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

let locale = "en";
if (navigator.language) {
    locale = navigator.language.substring(0, 2).toLowerCase()
}

if (locale == 'pt') {
    klang = klang.portuguese
} else if (locale == 'fr') {
    klang = klang.french
} else if (locale == 'es') {
    klang = klang.spanish
} else {
    klang = klang.english
}

let id = getParameterByName("id");
let address = getParameterByName("address");
let phoneRE = new RegExp(/[[0-9]+[-][0-9]+/);
let emailRE = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);

if (phoneRE.test(id)) {
    preloader_div.removeAttribute("hidden");
    sms_token.value = address;
    c_code.value = "+" + id.split("-")[0];
    p_number.value = id.split("-")[1];
    sms_button.click()
} else if (emailRE.test(id)) {
    preloader_div.removeAttribute("hidden");
    email_token.value = address;
    e_mail.value = id;
    email_button.click()
} else {
    chip_div.removeAttribute("hidden");
    msg_span.innerHTML = klang.invalid_username
}


/**
 * For search queries
 * @param {string} name
 * @param {string} url
 * @returns {string}
 */
function getParameterByName(name, url) {
    if (!url) {
        url = window.location.href
    }
    name = name.replace(/[\[\]]/g, "\\$&");
    let regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)"),
        results = regex.exec(url);
    if (!results) {
        return null
    }
    if (!results[2]) {
        return ''
    }
    return decodeURIComponent(results[2].replace(/\+/g, " "))
}