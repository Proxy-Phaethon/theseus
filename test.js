const API_URL = "https://example.com/api";
const retries = 3;

function fetchUser(id) {
    return fetch(`${API_URL}/users/${id}`);
}

class UserManager {
    constructor(name) {
        this.name = name;
    }

    getName() {
        return this.name;
    }
}

export { fetchUser, UserManager };