<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    #[Route(path: '/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();

        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);
    }

    #[Route(path: '/logout', name: 'app_logout')]
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }

    #[Route(path: '/api/login', name: 'api_login')]
    public function api_login(
        Request $request,
        UserRepository $userRepository,
        UserPasswordHasherInterface $userPasswordHasher
    ): JsonResponse
    {
        $body = json_decode($request->getContent(), true);

        if(!isset($body['firstname'], $body['lastname'], $body['email'], $body['password'])){
            return $this->json(['error' => 'Données invalides'], 400);
        }
      
        /** @var User|null */
        $user = $userRepository->findBy(['email' => $body['email']]);
        if (!$user) {
            return $this->json(['error' => 'Utilisateur introuvable'], 400);
        }
        echo gettype($user);
        if (!$userPasswordHasher->isPasswordValid($user, $body['password'])) {
            return $this->json(['error' => 'Utilisateur introuvable'], 400);
        }

        return $this->json([
            'success' => 'Utilisateur trouvé',
            'user' => $user,
        ], 200);
    }
}
