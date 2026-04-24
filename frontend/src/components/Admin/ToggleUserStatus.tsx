import { useMutation, useQueryClient } from "@tanstack/react-query"
import { CircleOff, RotateCcw } from "lucide-react"
import { useState } from "react"
import { useForm } from "react-hook-form"

import { type UserPublic, UsersService } from "@/client"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { DropdownMenuItem } from "@/components/ui/dropdown-menu"
import { LoadingButton } from "@/components/ui/loading-button"
import useCustomToast from "@/hooks/useCustomToast"
import { handleError } from "@/utils"

interface ToggleUserStatusProps {
  user: UserPublic
  onSuccess: () => void
}

const ToggleUserStatus = ({ user, onSuccess }: ToggleUserStatusProps) => {
  const [isOpen, setIsOpen] = useState(false)
  const queryClient = useQueryClient()
  const { showSuccessToast, showErrorToast } = useCustomToast()
  const { handleSubmit } = useForm()

  const nextIsActive = !user.is_active
  const actionLabel = nextIsActive ? "Reactivate" : "Suspend"
  const menuLabel = `${actionLabel} User`
  const dialogTitle = `${actionLabel} User`
  const dialogDescription = nextIsActive
    ? "This user will regain access to the application immediately."
    : "This user will lose access to the application immediately and will not be able to sign in until reactivated."
  const successMessage = nextIsActive
    ? "User reactivated successfully"
    : "User suspended successfully"

  const mutation = useMutation({
    mutationFn: async () => {
      await UsersService.updateUser({
        userId: user.id,
        requestBody: { is_active: nextIsActive },
      })
    },
    onSuccess: () => {
      showSuccessToast(successMessage)
      setIsOpen(false)
      onSuccess()
    },
    onError: handleError.bind(showErrorToast),
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] })
    },
  })

  const onSubmit = async () => {
    mutation.mutate()
  }

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuItem
        variant={nextIsActive ? "default" : "destructive"}
        onSelect={(e) => e.preventDefault()}
        onClick={() => setIsOpen(true)}
      >
        {nextIsActive ? <RotateCcw /> : <CircleOff />}
        {menuLabel}
      </DropdownMenuItem>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={handleSubmit(onSubmit)}>
          <DialogHeader>
            <DialogTitle>{dialogTitle}</DialogTitle>
            <DialogDescription>{dialogDescription}</DialogDescription>
          </DialogHeader>

          <DialogFooter className="mt-4">
            <DialogClose asChild>
              <Button variant="outline" disabled={mutation.isPending}>
                Cancel
              </Button>
            </DialogClose>
            <LoadingButton
              variant={nextIsActive ? "default" : "destructive"}
              type="submit"
              loading={mutation.isPending}
            >
              {actionLabel}
            </LoadingButton>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export default ToggleUserStatus