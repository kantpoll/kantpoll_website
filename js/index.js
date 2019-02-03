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

if (localStorage.getItem("words")) {
    if (window.location.href.startsWith("http://127.0.0.1")){
        window.location.href = "http://127.0.0.1:1985/home.html"
    } else if (window.location.href.startsWith("http://localhost")){
        window.location.href = "http://localhost:1985/home.html"
    }
} else {
    if (window.location.href.startsWith("http://127.0.0.1")){
        window.location.href = "http://127.0.0.1:1985/login.html"
    } else if (window.location.href.startsWith("http://localhost")){
        window.location.href = "http://localhost:1985/login.html"
    }
}