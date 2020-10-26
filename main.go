package main

import (
	"context"
	"github.com/rs/zerolog/log"
	msgraph "github.com/yaegashi/msgraph.go/beta"
	"github.com/yaegashi/msgraph.go/msauth"
	"golang.org/x/oauth2"
	"os"
	"strings"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const CHECK_INTERVAL = 5 * time.Minute

func main() {
	log.Info().Msg("Started Azure CRB manager")

	clientID := os.Getenv("AZURE_CLIENT_ID")
	if len(clientID) == 0 {
		log.Fatal().Msgf("Environment variable AZURE_CLIENT_ID missing")
	}
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	if len(clientSecret) == 0 {
		log.Fatal().Msgf("Environment variable AZURE_CLIENT_SECRET missing")
	}
	groupID := os.Getenv("AZURE_AD_GROUP_ID")
	if len(groupID) == 0 {
		log.Fatal().Msgf("Environment variable AZURE_AD_GROUP_ID missing")
	}

	for {
		// Get AAD users
		aadUsers, err := GetUsersForGroup(
			clientID,
			clientSecret,
			groupID)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get list of users from Azure AD")
			<-time.After(CHECK_INTERVAL)
			continue
		}

		// Get Kube users
		kubeUsers, err := GetCRBsFromKube()
		if err != nil {
			log.Error().Err(err).Msg("Failed to get list of clusterroles from Kubernetes")
			<-time.After(CHECK_INTERVAL)
			continue
		}

		// Delete users
		err = DeleteCRBsFromKube(aadUsers, kubeUsers)
		if err != nil {
			log.Error().Err(err).Msg("Failed to delete CRBs from Kubernetes")
			<-time.After(CHECK_INTERVAL)
			continue
		}

		// Add users
		err = AddCRBsToKube(aadUsers, kubeUsers)
		if err != nil {
			log.Error().Err(err).Msg("Failed to add CRBs from Kubernetes")
			<-time.After(CHECK_INTERVAL)
			continue
		}

		<-time.After(CHECK_INTERVAL)
	}
}

func GetUsersForGroup(clientID, clientSecret, groupID string) (map[string]string, error) {
	users := make(map[string]string)

	ctx := context.TODO()
	m := msauth.NewManager()
	scopes := []string{msauth.DefaultMSGraphScope}
	ts, err := m.ClientCredentialsGrant(ctx, "a6e2367a-92ea-4e5a-b565-723830bcc095",
		clientID, clientSecret, scopes)
	if err != nil {
		return users, err
	}

	httpClient := oauth2.NewClient(ctx, ts)
	graphClient := msgraph.NewClient(httpClient)

	r := graphClient.Groups().ID(groupID).TransitiveMembers().Request()
	objs, err := r.Get(ctx)
	if err != nil {
		return users, err
	}

	for _, user := range objs {
		if user.AdditionalData["@odata.type"].(string) == "#microsoft.graph.group" {
			continue
		}
		displayName := user.AdditionalData["displayName"].(string)
		email := user.AdditionalData["mail"].(string)
		log.Debug().Msgf("Discovered AAD user %s", displayName)
		users[email] = displayName
	}

	return users, nil
}

func GetCRBsFromKube() (map[string]string, error) {
	crds := make(map[string]string)

	config, err := rest.InClusterConfig()
	if err != nil {
		return crds, err
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return crds, err
	}

	ctx := context.TODO()
	crdList, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return crds, err
	}

	for _, crd := range crdList.Items {
		for _, subject := range crd.Subjects {
			if subject.Kind != "user" && !strings.HasPrefix(subject.Name, "aad:") {
				continue
			}
			user := strings.TrimPrefix(subject.Name, "aad:")
			crds[user] = crd.Name
			break
		}
	}

	return crds, nil
}

func DeleteCRBsFromKube(aadUsers, kubeUsers map[string]string) error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	toDelete := make([]string, 0)

	for email, crdName := range kubeUsers {
		if _, exists := aadUsers[email]; !exists {
			log.Info().Msgf("Removing %s", email)
			toDelete = append(toDelete, crdName)
		}
	}

	for _, crdName := range toDelete {
		ctx := context.TODO()
		if err = clientset.RbacV1().ClusterRoleBindings().Delete(ctx, crdName, metav1.DeleteOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func AddCRBsToKube(aadUsers, kubeUsers map[string]string) error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	toAdd := make([]string, 0)

	for email := range aadUsers {
		if _, exists := kubeUsers[email]; !exists {
			log.Info().Msgf("Adding %s", email)
			toAdd = append(toAdd, email)
		}
	}

	for _, email := range toAdd {
		ctx := context.TODO()

		crd := rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: email,
				Annotations: map[string]string{
					"bink.com/managedby": "kube-crb-manager",
				},
			},
			Subjects: []rbacv1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "User",
					Name:     "aad:" + email,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "cluster-admin",
			},
		}

		if _, err = clientset.RbacV1().ClusterRoleBindings().Create(ctx, &crd, metav1.CreateOptions{}); err != nil {
			return err
		}
	}

	return nil
}
