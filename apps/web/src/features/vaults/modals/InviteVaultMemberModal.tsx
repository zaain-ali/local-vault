import { zodResolver } from "@hookform/resolvers/zod";
import { Controller, useForm } from "react-hook-form";
import { z } from "zod";

import {
	Button,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
	Field,
	FieldError,
	FieldLabel,
	Input,
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "#/components/ui";
import { useAddVaultMember } from "#/features/vaults/hooks";
import { useModalStore } from "#/stores/useModalStore";

const schema = z.object({
	email: z.email({ message: "Enter a valid email address." }),
	role: z.enum(["admin", "member"]),
});

type Values = z.infer<typeof schema>;

export function InviteVaultMemberModal() {
	const closeModal = useModalStore((s) => s.closeModal);
	const props = useModalStore((s) => s.props);
	const vaultId = String(props.vaultId ?? "");
	const envs = (props.envs as string[] | undefined) ?? [
		"development",
		"staging",
		"production",
	];
	const add = useAddVaultMember(vaultId);
	const {
		register,
		control,
		handleSubmit,
		formState: { errors },
	} = useForm<Values>({
		resolver: zodResolver(schema),
		defaultValues: { email: "", role: "member" },
	});

	const onSubmit = handleSubmit((values) => {
		const env_access = envs.map((env) => ({
			env,
			permission:
				values.role === "admin" || env === "development"
					? ("write" as const)
					: ("read" as const),
		}));
		add.mutate(
			{ email: values.email, role: values.role, env_access },
			{ onSuccess: () => closeModal() },
		);
	});

	return (
		<DialogContent>
			<DialogHeader>
				<DialogTitle>Add vault member</DialogTitle>
				<DialogDescription>
					They must already be a workspace member. After they upload account
					keys, verify their fingerprint and grant the vault key from the CLI:
					<code className="ml-1 font-mono">lv access grant</code>
				</DialogDescription>
			</DialogHeader>
			<form
				id="invite-vault-member-form"
				onSubmit={onSubmit}
				noValidate
				className="grid gap-4"
			>
				<Field data-invalid={!!errors.email}>
					<FieldLabel htmlFor="vault-invite-email">Email address</FieldLabel>
					<Input
						id="vault-invite-email"
						type="email"
						autoFocus
						placeholder="name@company.com"
						aria-invalid={!!errors.email}
						{...register("email")}
					/>
					<FieldError errors={[errors.email]} />
				</Field>
				<Field data-invalid={!!errors.role}>
					<FieldLabel htmlFor="vault-invite-role">Role</FieldLabel>
					<Controller
						control={control}
						name="role"
						render={({ field }) => (
							<Select value={field.value} onValueChange={field.onChange}>
								<SelectTrigger id="vault-invite-role">
									<SelectValue />
								</SelectTrigger>
								<SelectContent>
									<SelectItem value="member">Member</SelectItem>
									<SelectItem value="admin">Admin</SelectItem>
								</SelectContent>
							</Select>
						)}
					/>
					<FieldError errors={[errors.role]} />
				</Field>
			</form>
			<DialogFooter>
				<Button variant="ghost" onClick={closeModal}>
					Cancel
				</Button>
				<Button
					type="submit"
					form="invite-vault-member-form"
					disabled={add.isPending}
				>
					Add member
				</Button>
			</DialogFooter>
		</DialogContent>
	);
}
