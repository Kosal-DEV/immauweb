<?php

namespace App\Entity;

use ApiPlatform\Metadata\ApiResource;
use App\Repository\FavorisRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: FavorisRepository::class)]
#[ApiResource()]
class Favoris
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    /**
     * @var Collection<int, Annonces>
     */
    #[ORM\OneToMany(targetEntity: Annonces::class, mappedBy: 'favoris', orphanRemoval: true)]
    private Collection $annonces;

    #[ORM\ManyToOne(inversedBy: 'favoris')]
    #[ORM\JoinColumn(nullable: false)]
    private ?User $user = null;

    public function __construct()
    {
        $this->annonces = new ArrayCollection();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function setId(int $id): static
    {
        $this->id = $id;

        return $this;
    }

    /**
     * @return Collection<int, Annonces>
     */
    public function getAnnonces(): Collection
    {
        return $this->annonces;
    }

    public function addAnnonce(Annonces $annonce): static
    {
        if (!$this->annonces->contains($annonce)) {
            $this->annonces->add($annonce);
            $annonce->setFavoris($this);
        }

        return $this;
    }

    public function removeAnnonce(Annonces $annonce): static
    {
        if ($this->annonces->removeElement($annonce)) {
            // set the owning side to null (unless already changed)
            if ($annonce->getFavoris() === $this) {
                $annonce->setFavoris(null);
            }
        }

        return $this;
    }

    public function getUser(): ?User
    {
        return $this->user;
    }

    public function setUser(?User $user): static
    {
        $this->user = $user;

        return $this;
    }
}
