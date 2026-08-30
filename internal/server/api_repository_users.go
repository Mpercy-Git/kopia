package server

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/kopia/kopia/internal/serverapi"
	"github.com/kopia/kopia/internal/user"
	"github.com/kopia/kopia/repo"
)

func handleRepositoryUserList(ctx context.Context, rc requestContext) (any, *apiError) {
	profiles, err := user.ListUserProfiles(ctx, rc.rep)
	if err != nil {
		return nil, internalServerError(err)
	}

	users := make([]serverapi.RepositoryUser, 0, len(profiles))

	for _, p := range profiles {
		users = append(users, serverapi.RepositoryUser{Username: p.Username})
	}

	return &serverapi.RepositoryUsersResponse{Users: users}, nil
}

func handleRepositoryUserCreate(ctx context.Context, rc requestContext) (any, *apiError) {
	var req serverapi.CreateRepositoryUserRequest

	if err := json.Unmarshal(rc.body, &req); err != nil {
		return nil, unableToDecodeRequest(err)
	}

	if err := user.ValidateUsername(req.Username); err != nil {
		return nil, requestError(serverapi.ErrorMalformedRequest, err.Error())
	}

	if req.Password == "" {
		return nil, requestError(serverapi.ErrorMalformedRequest, "password is required")
	}

	if err := repo.WriteSession(ctx, rc.rep, repo.WriteSessionOptions{
		Purpose: "RepositoryUserCreate",
	}, func(ctx context.Context, w repo.RepositoryWriter) error {
		p, err := user.GetNewProfile(ctx, w, req.Username)
		if err != nil {
			return errors.Wrap(err, "unable to create user profile")
		}

		if err := p.SetPassword(req.Password); err != nil {
			return errors.Wrap(err, "error setting password")
		}

		return user.SetUserProfile(ctx, w, p)
	}); err != nil {
		return nil, userProfileErrorToAPIError(err)
	}

	// make the new account usable without waiting for the periodic refresh.
	rc.srv.Refresh()

	return &serverapi.Empty{}, nil
}

func handleRepositoryUserSetPassword(ctx context.Context, rc requestContext) (any, *apiError) {
	var req serverapi.SetRepositoryUserPasswordRequest

	if err := json.Unmarshal(rc.body, &req); err != nil {
		return nil, unableToDecodeRequest(err)
	}

	if req.Password == "" {
		return nil, requestError(serverapi.ErrorMalformedRequest, "password is required")
	}

	username := rc.muxVar("username")

	if err := repo.WriteSession(ctx, rc.rep, repo.WriteSessionOptions{
		Purpose: "RepositoryUserSetPassword",
	}, func(ctx context.Context, w repo.RepositoryWriter) error {
		p, err := user.GetUserProfile(ctx, w, username)
		if err != nil {
			return errors.Wrap(err, "unable to get user profile")
		}

		if err := p.SetPassword(req.Password); err != nil {
			return errors.Wrap(err, "error setting password")
		}

		return user.SetUserProfile(ctx, w, p)
	}); err != nil {
		return nil, userProfileErrorToAPIError(err)
	}

	rc.srv.Refresh()

	return &serverapi.Empty{}, nil
}

func handleRepositoryUserDelete(ctx context.Context, rc requestContext) (any, *apiError) {
	username := rc.muxVar("username")

	if err := repo.WriteSession(ctx, rc.rep, repo.WriteSessionOptions{
		Purpose: "RepositoryUserDelete",
	}, func(ctx context.Context, w repo.RepositoryWriter) error {
		if _, err := user.GetUserProfile(ctx, w, username); err != nil {
			return errors.Wrap(err, "unable to get user profile")
		}

		return user.DeleteUserProfile(ctx, w, username)
	}); err != nil {
		return nil, userProfileErrorToAPIError(err)
	}

	rc.srv.Refresh()

	return &serverapi.Empty{}, nil
}

func userProfileErrorToAPIError(err error) *apiError {
	switch {
	case errors.Is(err, user.ErrUserAlreadyExists):
		return requestError(serverapi.ErrorAlreadyExists, err.Error())
	case errors.Is(err, user.ErrUserNotFound):
		return notFoundError(err.Error())
	default:
		return internalServerError(err)
	}
}
