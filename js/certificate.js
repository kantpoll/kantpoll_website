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

document.title = klang.your_certificate;
button1.innerHTML = klang.copy;

button1.addEventListener("click", function () {
    textarea1.select();
    document.execCommand("copy");
    Materialize.toast(klang.copied, 2500, 'rounded')
});