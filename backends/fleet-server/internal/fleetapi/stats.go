package fleetapi

import "net/http"

func (a *API) stats(w http.ResponseWriter, r *http.Request) {
	s, err := a.DB.Stats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s)
}
