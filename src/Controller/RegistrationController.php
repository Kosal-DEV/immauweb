<?php

namespace App\Controller;

use App\Entity\User;
use App\Security\EmailVerifier;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Mime\Address;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Contracts\Translation\TranslatorInterface;
use SymfonyCasts\Bundle\VerifyEmail\Exception\VerifyEmailExceptionInterface;

class RegistrationController extends AbstractController
{
    private EmailVerifier $emailVerifier;

    public function __construct(EmailVerifier $emailVerifier)
    {
        $this->emailVerifier = $emailVerifier;
    }

    #[Route('/api/register', name: 'app_register', methods: ['POST'])]
    public function register(Request $request, UserPasswordHasherInterface $userPasswordHasher, EntityManagerInterface $entityManager): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $firstname = $data['firstname'];
        $lastname = $data['lastname'];
        $email = $data['email'];
        $plainPassword = $data['plainPassword'];
        $role = $data['role'] ?? 'ROLE_USER';

        if (!$email || !$plainPassword) {
            return $this->json(['error' => 'Email and password are required'], 400);
        }

        $user = new User();
        $user->setFirstname($firstname);
        $user->setLastname($lastname);
        $user->setEmail($email);
        $user->setPassword($userPasswordHasher->hashPassword($user, $plainPassword));
        $user->setRoles([$role]);

        $entityManager->persist($user);
        $entityManager->flush();

        // Envoi de l’email de confirmation
        $this->emailVerifier->sendEmailConfirmation(
            'app_verify_email',
            $user,
            (new TemplatedEmail())
                ->from(new Address('noreply@immauweb.be', 'Immauweb'))
                ->to($user->getEmail())
                ->subject('Please Confirm your Email')
                ->htmlTemplate('registration/confirmation_email.html.twig')
        );

        return $this->json(['message' => 'User created successfully, please verify your email'], 201);
    }

    #[Route('/verify/email', name: 'app_verify_email')]
    public function verifyUserEmail(Request $request, TranslatorInterface $translator, EntityManagerInterface $entityManager): JsonResponse
    {
        $id = $request->query->get('id'); // récupère l’ID depuis l’URL (test simplifié)
        if (!$id) {
            return $this->json(['error' => 'Invalid verification link'], 400);
        }

        $user = $entityManager->getRepository(User::class)->find($id);
        if (!$user) {
            return $this->json(['error' => 'User not found'], 404);
        }

        try {
            $this->emailVerifier->handleEmailConfirmation($request, $user);
        } catch (VerifyEmailExceptionInterface $exception) {
            return $this->json([
                'error' => $translator->trans($exception->getReason(), [], 'VerifyEmailBundle')
            ], 400);
        }

        return $this->json(['message' => 'Email verified successfully']);
    }
}
