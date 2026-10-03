import EventDetail from "@/components/EventDetail";

export default async function Page({ params }: PageProps<"/security/events/[id]">) {
  const { id } = await params;
  return <EventDetail id={id} />;
}
